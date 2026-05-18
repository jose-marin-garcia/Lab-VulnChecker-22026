package com.devsecops.vulncheckerbackend.services;

import com.jcraft.jsch.Session;
import com.devsecops.vulncheckerbackend.config.SshTunnelManager;
import com.devsecops.vulncheckerbackend.dto.WazuhCredentials;
import com.devsecops.vulncheckerbackend.entities.VulnerabilityEntity;
import com.devsecops.vulncheckerbackend.entities.VulnerabilitySnapshotEntity;
import com.devsecops.vulncheckerbackend.repositories.VulnerabilityRepository;
import com.devsecops.vulncheckerbackend.repositories.VulnerabilitySnapshotRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executor;

@Service
public class WazuhService {

    private static final Logger log = LoggerFactory.getLogger(WazuhService.class);

    private final SshTunnelManager tunnelManager;
    private final RestTemplate restTemplate;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final VulnerabilitySnapshotRepository snapshotRepository;
    private final Executor taskExecutor;

    @Value("${wazuh.index.vulnerabilities}")
    private String vulnIndex;

    @Value("${wazuh.index.monitoring}")
    private String monitoringIndex;

    public WazuhService(SshTunnelManager tunnelManager,
                        @Qualifier("wazuhRestTemplate") RestTemplate restTemplate,
                        VulnerabilityRepository vulnerabilityRepository,
                        VulnerabilitySnapshotRepository snapshotRepository,
                        @Qualifier("wazuhTaskExecutor") Executor taskExecutor) {
        this.tunnelManager = tunnelManager;
        this.restTemplate = restTemplate;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.snapshotRepository = snapshotRepository;
        this.taskExecutor = taskExecutor;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  AUTENTICACIÓN JWT vs Basic Auth
    // ─────────────────────────────────────────────────────────────────────────
    //
    //  En Wazuh 4.8+ el endpoint /vulnerability de la API fue eliminado.
    //  La forma recomendada de obtener vulnerabilidades es consultar
    //  directamente el Wazuh Indexer (OpenSearch) en el puerto 9200.
    //
    //  Este servicio ofrece DOS modos:
    //
    //  A) API Wazuh (puerto 55000) — con JWT para endpoints que aún existen:
    //     - GET /agents?select=id,name,group  → grupos de agentes
    //
    //  B) Indexer (puerto 9200) — con Basic Auth para datos de vulnerabilidad:
    //     - POST /{vulnIndex}/_search        → consultas de vulns
    //     - GET /{vulnIndex}/_count          → conteo total
    //
    //  Si el Indexer está configurado para aceptar JWT, cambiar BearerAuth
    //  en search() por el token retornado desde authenticate().

    // ─────────────────────────────────────────────────────────────────────────
    //  1. JWT — Autenticación contra la API de Wazuh (puerto 55000)
    // ─────────────────────────────────────────────────────────────────────────

    private String authenticate(String user, String password, int apiLocalPort) {
        String url = "https://127.0.0.1:" + apiLocalPort + "/security/user/authenticate";

        String auth = user + ":" + password;
        String encoded = Base64.getEncoder().encodeToString(auth.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Basic " + encoded);

        ResponseEntity<Map> response = restTemplate.exchange(
                url, HttpMethod.POST, new HttpEntity<>(headers), Map.class
        );

        Map body = response.getBody();
        if (body != null && body.containsKey("data")) {
            Map data = (Map) body.get("data");
            String token = (String) data.get("token");
            log.info("JWT obtenido exitosamente desde API Wazuh.");
            return token;
        }
        throw new RuntimeException("No se pudo obtener JWT de la API Wazuh: " + body);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  2. API Wazuh — Llamada con JWT (para endpoints que aún existen)
    // ─────────────────────────────────────────────────────────────────────────

    private Map<String, Object> callApiWithJwt(String endpoint, String jwt, int apiLocalPort) {
        String url = "https://127.0.0.1:" + apiLocalPort + endpoint;

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + jwt);
        headers.setContentType(MediaType.APPLICATION_JSON);

        ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                url, HttpMethod.GET, new HttpEntity<>(headers),
                new org.springframework.core.ParameterizedTypeReference<Map<String, Object>>() {}
        );

        return response.getBody();
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  3. MÉTODOS PÚBLICOS — Live queries (indexer con Basic Auth)
    // ─────────────────────────────────────────────────────────────────────────
    //
    //  Estos endpoints devuelven el JSON crudo de OpenSearch para
    //  el frontend. Se mantienen con Basic Auth contra el indexer.

    public Map<String, Object> getAllVulnerabilities(WazuhCredentials creds, int limit, int offset) throws Exception {
        int pageSize = Math.min(limit, 5000);

        String body = """
                {
                  "from": %d,
                  "size": %d,
                  "query": { "match_all": {} },
                  "sort": [{ "vulnerability.detected_at": "desc" }]
                }
                """.formatted(offset, pageSize);

        return executeWithTunnel(creds, body);
    }

    public Map<String, Object> getTopVulnerabilities(WazuhCredentials creds, int limit) throws Exception {
        return getAllVulnerabilities(creds, limit, 0);
    }

    public Map<String, Object> getVulnerabilitiesBySeverity(WazuhCredentials creds, String severity, int limit) throws Exception {
        String body = """
                {
                  "size": %d,
                  "query": {
                    "match": { "vulnerability.severity": "%s" }
                  }
                }
                """.formatted(limit, severity.toLowerCase());
        return executeWithTunnel(creds, body);
    }

    public Map<String, Object> getVulnerabilitiesByAgent(WazuhCredentials creds, String agentId, int limit) throws Exception {
        String body = """
                {
                  "size": %d,
                  "query": {
                    "match": { "agent.id": "%s" }
                  }
                }
                """.formatted(limit, agentId);
        return executeWithTunnel(creds, body);
    }

    public Map<String, Object> getVulnerabilitiesByCve(WazuhCredentials creds, String cve) throws Exception {
        String body = """
                {
                  "size": 500,
                  "query": {
                    "match": { "vulnerability.id": "%s" }
                  }
                }
                """.formatted(cve.toUpperCase());
        return executeWithTunnel(creds, body);
    }

    public Map<String, Object> getCriticalVulnerabilities(WazuhCredentials creds) throws Exception {
        return getVulnerabilitiesBySeverity(creds, "critical", 500);
    }

    public Map<String, Object> getVulnerabilitiesSummary(WazuhCredentials creds) throws Exception {
        String body = """
                {
                  "size": 0,
                  "aggs": {
                    "by_severity": {
                      "terms": { "field": "vulnerability.severity" }
                    }
                  }
                }
                """;
        return executeWithTunnel(creds, body);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  4. INFRAESTRUCTURA — Túnel + consulta al Indexer
    // ─────────────────────────────────────────────────────────────────────────

    private Map<String, Object> executeWithTunnel(WazuhCredentials creds, String queryBody) throws Exception {
        log.info(">>> EJECUTANDO ACCESO: Host SSH: {} | Usuario SSH: {} | Indexer User: {}",
                creds.sshHost(), creds.sshUser(), creds.indexerUser());

        Session session = tunnelManager.openTunnel(creds.sshHost(), 22, creds.sshUser(), creds.sshPassword());
        try {
            return search(queryBody, creds.indexerUser(), creds.indexerPassword());
        } finally {
            tunnelManager.closeTunnel(session);
        }
    }

    private Map<String, Object> search(String queryBody, String user, String password) {
        String auth = user + ":" + password;
        String credentials = Base64.getEncoder().encodeToString(
                auth.getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Basic " + credentials);
        headers.setContentType(MediaType.APPLICATION_JSON);

        String url = wazuhBaseUrl() + "/" + vulnIndex + "/_search";

        ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                url, HttpMethod.POST, new HttpEntity<>(queryBody, headers),
                new org.springframework.core.ParameterizedTypeReference<Map<String, Object>>() {}
        );

        return response.getBody();
    }

    public long getRemoteTotalCount(WazuhCredentials creds) throws Exception {
        Session session = tunnelManager.openTunnel(creds.sshHost(), 22, creds.sshUser(), creds.sshPassword());
        try {
            String url = wazuhBaseUrl() + "/" + vulnIndex + "/_count";

            HttpHeaders headers = new HttpHeaders();
            String auth = creds.indexerUser() + ":" + creds.indexerPassword();
            String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
            headers.set("Authorization", "Basic " + encodedAuth);

            try {
                ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                        url, HttpMethod.GET, new HttpEntity<>(headers),
                        new org.springframework.core.ParameterizedTypeReference<Map<String, Object>>() {}
                );
                return Long.parseLong(response.getBody().get("count").toString());
            } catch (Exception e) {
                System.err.println("Error inesperado al conectarse con elasticSearch: " + e.getMessage());
                throw e;
            }


        } finally {
            tunnelManager.closeTunnel(session);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  5. Sincronización masiva — Obtiene agentes vía API Wazuh (JWT)
    //     y vulnerabilidades vía Indexer (Basic Auth)
    // ─────────────────────────────────────────────────────────────────────────

    public void syncAllVulnerabilitiesMasive(WazuhCredentials creds) {
        taskExecutor.execute(() -> {
            log.info("INICIANDO EXTRACCIÓN MASIVA PARA: {}", creds.sshHost());
            int pageSize = 5000;
            Object[] lastSortValues = null;
            boolean hasMore = true;
            long totalProcesados = 0;
            Map<String, SnapshotCounter> countersByAgent = new java.util.HashMap<>();

            try {
                LocalDateTime currentSyncTime = LocalDateTime.now();

                Session session = tunnelManager.openTunnel(creds.sshHost(), 22, creds.sshUser(), creds.sshPassword());
                try {
                    // Obtener grupos de agentes usando la API Wazuh (JWT)
                    Map<String, String> agentGroupsDict = fetchAgentGroupsViaApi(creds);

                    while (hasMore) {
                        String searchAfterClause = (lastSortValues != null)
                            ? ", \"search_after\": [%s, \"%s\"]".formatted(lastSortValues[0], lastSortValues[1])
                            : "";

                        String body = """
                            {
                            "size": %d,
                            "query": { "match_all": {} },
                            "sort": [
                                { "vulnerability.detected_at": "desc" },
                                { "_id": "asc" }
                            ]
                            %s
                            }
                            """.formatted(pageSize, searchAfterClause);

                        Map<String, Object> response = search(body, creds.indexerUser(), creds.indexerPassword());

                        if (response != null && response.containsKey("hits")) {
                            Map<String, Object> hitsStructure = (Map<String, Object>) response.get("hits");
                            List<Map<String, Object>> hits = (List<Map<String, Object>>) hitsStructure.get("hits");

                            if (hits == null || hits.isEmpty()) {
                                hasMore = false;
                            } else {
                                processAndSaveBatch(hits, countersByAgent, agentGroupsDict, currentSyncTime);

                                totalProcesados += hits.size();
                                lastSortValues = ((List<Object>) hits.get(hits.size() - 1).get("sort")).toArray();
                                log.info("[{}] Progreso: {} registros...", creds.sshHost(), totalProcesados);
                            }
                        } else { hasMore = false; }
                    }
                } finally {
                    countersByAgent.values().forEach(this::saveSnapshot);

                    if (!countersByAgent.isEmpty()) {
                        List<String> activeAgents = new java.util.ArrayList<>(countersByAgent.keySet());
                        vulnerabilityRepository.markAsResolvedForAgentsBefore(activeAgents, currentSyncTime, LocalDateTime.now());
                        log.info("Fase Sweep completada: vulnerabilidades antiguas marcadas como Resolved.");
                    }

                    tunnelManager.closeTunnel(session);
                    log.info("FINALIZADO: {} registros guardados de {}", totalProcesados, creds.sshHost());
                }
            } catch (Exception e) {
                log.error("ERROR CRÍTICO EN HILO DE SINCRONIZACIÓN: ", e);
            }
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  6. Grupos de agentes — vía API Wazuh con JWT
    // ─────────────────────────────────────────────────────────────────────────

    private Map<String, String> fetchAgentGroupsViaApi(WazuhCredentials creds) {
        Map<String, String> agentGroups = new java.util.HashMap<>();
        Session session = null;
        try {
            session = tunnelManager.openTunnel(
                    creds.sshHost(), 22, creds.sshUser(), creds.sshPassword(),
                    tunnelManager.getApiLocalPort(), 55000
            );

            String jwt = authenticate(creds.wazuhUser(), creds.wazuhPassword(), tunnelManager.getApiLocalPort());

            Map<String, Object> response = callApiWithJwt(
                    "/agents?select=id,name,group&limit=10000",
                    jwt,
                    tunnelManager.getApiLocalPort()
            );

            if (response != null && response.containsKey("data")) {
                Map<String, Object> data = (Map<String, Object>) response.get("data");
                List<Map<String, Object>> items = (List<Map<String, Object>>) data.get("affected_items");

                if (items != null) {
                    for (Map<String, Object> agent : items) {
                        String id = (String) agent.get("id");
                        if (id == null) continue;

                        Object groupObj = agent.get("group");
                        if (groupObj instanceof List list) {
                            agentGroups.put(id, String.join(",", list));
                        } else if (groupObj != null) {
                            agentGroups.put(id, groupObj.toString());
                        } else {
                            agentGroups.put(id, "default");
                        }
                    }
                }
            }
            log.info("Extraídos grupos de {} agentes exitosamente desde API Wazuh (JWT).", agentGroups.size());
        } catch (Exception e) {
            log.warn("Error obteniendo grupos vía API Wazuh, fallback a indexer: {}", e.getMessage());
            agentGroups = fetchAgentGroupsFallback(creds);
        } finally {
            if (session != null && session.isConnected()) {
                tunnelManager.closeTunnel(session);
            }
        }
        return agentGroups;
    }

    private Map<String, String> fetchAgentGroupsFallback(WazuhCredentials creds) {
        Map<String, String> agentGroups = new java.util.HashMap<>();
        try {
            String queryBody = """
                    {
                      "size": 10000,
                      "query": { "match_all": {} },
                      "_source": ["id", "group"]
                    }
                    """;

            String auth = creds.indexerUser() + ":" + creds.indexerPassword();
            String credentials = java.util.Base64.getEncoder().encodeToString(
                    auth.getBytes(java.nio.charset.StandardCharsets.UTF_8)
            );

            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "Basic " + credentials);
            headers.setContentType(MediaType.APPLICATION_JSON);

            String url = wazuhBaseUrl() + "/" + monitoringIndex + "/_search";

            ResponseEntity<Map> response = restTemplate.exchange(
                    url, HttpMethod.POST, new HttpEntity<>(queryBody, headers), Map.class
            );

            Map<String, Object> body = response.getBody();
            if (body != null && body.containsKey("hits")) {
                Map<String, Object> hitsObj = (Map<String, Object>) body.get("hits");
                if (hitsObj.containsKey("hits")) {
                    List<Map<String, Object>> hitsList = (List<Map<String, Object>>) hitsObj.get("hits");
                    for (Map<String, Object> hit : hitsList) {
                        Map<String, Object> source = (Map<String, Object>) hit.get("_source");
                        if (source != null && source.containsKey("id")) {
                            String id = source.get("id").toString();
                            Object groupObj = source.get("group");
                            if (groupObj instanceof java.util.List list) {
                                agentGroups.put(id, String.join(",", list));
                            } else if (groupObj != null) {
                                agentGroups.put(id, groupObj.toString());
                            } else {
                                agentGroups.put(id, "default");
                            }
                        }
                    }
                }
            }
            log.info("Extraídos grupos de {} agentes (fallback indexer).", agentGroups.size());
        } catch (Exception e) {
            log.error("Error obteniendo grupos desde indexer: {}", e.getMessage());
        }
        return agentGroups;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  7. Procesamiento de datos (sin cambios)
    // ─────────────────────────────────────────────────────────────────────────

    private void saveSnapshot(SnapshotCounter counter) {
        if (counter.agentId == null || counter.agentId.isEmpty()) return;

        VulnerabilitySnapshotEntity snap = new VulnerabilitySnapshotEntity();
        snap.setAgentId(counter.agentId);
        snap.setAgentName(counter.agentName);
        snap.setCriticalCount(counter.crit);
        snap.setHighCount(counter.high);
        snap.setMediumCount(counter.med);
        snap.setLowCount(counter.low);
        snap.setTotalCount(counter.getTotal());

        snapshotRepository.save(snap);

        log.info(">>> Snapshot capturado para Agente {}: Total {} vulnerabilidades.",
                counter.agentId, snap.getTotalCount());
    }

    private static class SnapshotCounter {
        String agentId = "";
        String agentName = "";
        int crit = 0;
        int high = 0;
        int med = 0;
        int low = 0;

        void count(Map<String, Object> source) {
            Map<String, Object> v = (Map<String, Object>) source.get("vulnerability");
            Map<String, Object> a = (Map<String, Object>) source.get("agent");
            this.agentId = (String) a.get("id");
            Object name = a.get("name");
            if (name != null && !name.toString().isBlank()) {
                this.agentName = name.toString();
            }
            String severity = (String) v.get("severity");

            if ("Critical".equalsIgnoreCase(severity)) crit++;
            else if ("High".equalsIgnoreCase(severity)) high++;
            else if ("Medium".equalsIgnoreCase(severity)) med++;
            else if ("Low".equalsIgnoreCase(severity)) low++;
        }

        int getTotal() { return crit + high + med + low; }
    }

    private void processAndSaveBatch(List<Map<String, Object>> hits, Map<String, SnapshotCounter> countersByAgent, Map<String, String> agentGroupsDict, LocalDateTime currentSyncTime) {
        List<VulnerabilityEntity> entitiesToSave = new java.util.ArrayList<>();

        for (Map<String, Object> hit : hits) {
            try {
                Map<String, Object> source = (Map<String, Object>) hit.get("_source");
                Map<String, Object> v = (Map<String, Object>) source.get("vulnerability");
                Map<String, Object> a = (Map<String, Object>) source.get("agent");
                Map<String, Object> p = (Map<String, Object>) source.get("package");

                String cve = (String) v.get("id");
                String agentId = (String) a.get("id");
                String pkgName = (String) p.get("name");

                countersByAgent.computeIfAbsent(agentId, ignored -> new SnapshotCounter()).count(source);

                java.util.Optional<VulnerabilityEntity> optEntity = vulnerabilityRepository.findByCveAndAgentIdAndPackageName(cve, agentId, pkgName);
                VulnerabilityEntity entity;

                if (optEntity.isPresent()) {
                    entity = optEntity.get();
                    entity.setLastSync(currentSyncTime);
                    entity.setStatus("Active");
                    entity.setResolvedAt(null);
                } else {
                    entity = new VulnerabilityEntity();
                    entity.setCve(cve);
                    entity.setAgentId(agentId);
                    entity.setLastSync(currentSyncTime);
                }
                entity.setAgentName((String) a.get("name"));

                String assignedGroup = agentGroupsDict.get(agentId);
                if (assignedGroup == null || assignedGroup.isBlank()) {
                    assignedGroup = "default";
                }
                entity.setAgentGroup(assignedGroup);

                entity.setPackageName(pkgName);
                entity.setPackageVersion((String) p.get("version"));
                entity.setSeverity((String) v.get("severity"));
                entity.setStatus("Active");

                Map<String, Object> scoreObj = (Map<String, Object>) v.get("score");
                if (scoreObj != null && scoreObj.get("base") != null) {
                    entity.setCvss3Score(Double.valueOf(scoreObj.get("base").toString()));
                }

                Object detectedAt = v.get("detected_at");
                if (detectedAt != null) {
                    try {
                        if (detectedAt instanceof Number num) {
                            long ms = num.longValue();
                            if (ms > 1_000_000_000_000L) entity.setDetectionTime(Instant.ofEpochMilli(ms).atZone(java.time.ZoneId.systemDefault()).toLocalDateTime());
                            else entity.setDetectionTime(Instant.ofEpochSecond(ms).atZone(java.time.ZoneId.systemDefault()).toLocalDateTime());
                        } else {
                            String s = detectedAt.toString();
                            if (!s.isBlank()) entity.setDetectionTime(ZonedDateTime.parse(s).toLocalDateTime());
                        }
                    } catch (Exception ignored) {
                    }
                }

                Object desc = v.get("description");
                if (desc != null) entity.setDescription(desc.toString());
                Object titleObj = v.get("title");
                if (titleObj != null) entity.setTitle(titleObj.toString());

                entitiesToSave.add(entity);
            } catch (Exception e) {
                log.warn("Hit malformado omitido: {}", e.getMessage());
            }
        }
        if (!entitiesToSave.isEmpty()) {
            vulnerabilityRepository.saveAll(entitiesToSave);
        }
    }

    private String wazuhBaseUrl() {
        return "https://127.0.0.1:" + tunnelManager.getLocalPort();
    }
}
