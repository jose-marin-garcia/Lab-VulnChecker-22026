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

    // 1. Uso de Logger en lugar de System.out (Code Smell: Major)
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
    //  MÉTODOS PÚBLICOS
    // ─────────────────────────────────────────────────────────────────────────

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
    //  INFRAESTRUCTURA
    // ─────────────────────────────────────────────────────────────────────────

    private Map<String, Object> executeWithTunnel(WazuhCredentials creds, String queryBody) throws Exception {
        // Este es el log que verás en tu consola de IntelliJ/Eclipse
        log.info(">>> EJECUTANDO ACCESO: Host SSH: {} | Usuario SSH: {} | Usuario Wazuh: {}", 
                creds.sshHost(), creds.sshUser(), creds.wazuhUser());

        Session session = tunnelManager.openTunnel(creds.sshHost(), 22, creds.sshUser(), creds.sshPassword());
        try {
            return search(queryBody, creds.wazuhUser(), creds.wazuhPassword());
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
        // Abrimos túnel solo para esta consulta rápida
        Session session = tunnelManager.openTunnel(creds.sshHost(), 22, creds.sshUser(), creds.sshPassword());
        try {
            String url = wazuhBaseUrl() + "/" + vulnIndex + "/_count";
            
            HttpHeaders headers = new HttpHeaders();
            String auth = creds.wazuhUser() + ":" + creds.wazuhPassword();
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

        // Al guardar, JPA usará el @PrePersist para setear 'snapshotDate' con LocalDateTime.now()
        snapshotRepository.save(snap);
        
        log.info(">>> Snapshot capturado para Agente {}: Total {} vulnerabilidades.", 
                counter.agentId, snap.getTotalCount());
    }

    // Clase interna para manejar el conteo sin ensuciar el método principal
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
                // Abrimos túnel específico para este hilo
                Session session = tunnelManager.openTunnel(creds.sshHost(), 22, creds.sshUser(), creds.sshPassword());
                try {
                    Map<String, String> agentGroupsDict = fetchAgentGroups(creds);

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

                        Map<String, Object> response = search(body, creds.wazuhUser(), creds.wazuhPassword());
                        
                        if (response != null && response.containsKey("hits")) {
                            Map<String, Object> hitsStructure = (Map<String, Object>) response.get("hits");
                            List<Map<String, Object>> hits = (List<Map<String, Object>>) hitsStructure.get("hits");

                            if (hits == null || hits.isEmpty()) {
                                hasMore = false;
                            } else {
                                // PROCESAR Y GUARDAR EN BLOQUE
                                processAndSaveBatch(hits, countersByAgent, agentGroupsDict, currentSyncTime);
                                
                                totalProcesados += hits.size();
                                lastSortValues = ((List<Object>) hits.get(hits.size() - 1).get("sort")).toArray();
                                log.info("[{}] Progreso: {} registros...", creds.sshHost(), totalProcesados);
                            }
                        } else { hasMore = false; }
                    }
                } finally {
                    countersByAgent.values().forEach(this::saveSnapshot);
                    
                    // Fase Sweep: Marcar como resueltas las vulnerabilidades que no vimos hoy
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
                    // Si ya existía, la actualizamos para que no la barra el Sweep
                    entity.setLastSync(currentSyncTime);
                    entity.setStatus("Active");
                    entity.setResolvedAt(null);
                } else {
                    // Si no existía, la creamos nueva
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
                        // Formato de fecha no reconocido; se deja detectionTime null
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

    private Map<String, String> fetchAgentGroups(WazuhCredentials creds) {
        Map<String, String> agentGroups = new java.util.HashMap<>();
        try {
            String queryBody = """
                    {
                      "size": 10000,
                      "query": { "match_all": {} },
                      "_source": ["id", "group"]
                    }
                    """;
            
            String auth = creds.wazuhUser() + ":" + creds.wazuhPassword();
            String credentials = java.util.Base64.getEncoder().encodeToString(
                    auth.getBytes(java.nio.charset.StandardCharsets.UTF_8)
            );

            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "Basic " + credentials);
            headers.setContentType(MediaType.APPLICATION_JSON);

            // Consultamos el índice de monitoreo de agentes en vez de la API
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
            log.info("Extraídos grupos de {} agentes exitosamente desde Elasticsearch", agentGroups.size());
        } catch (Exception e) {
            log.error("Error obteniendo grupos de agentes desde Elasticsearch: {}", e.getMessage());
        }
        return agentGroups;
    }
}
