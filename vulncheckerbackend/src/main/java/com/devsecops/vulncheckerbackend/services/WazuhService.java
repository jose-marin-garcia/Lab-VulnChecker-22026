package com.devsecops.vulncheckerbackend.services;

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
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executor;

@Service
public class WazuhService {

    // 1. Uso de Logger en lugar de System.out (Code Smell: Major)
    private static final Logger log = LoggerFactory.getLogger(WazuhService.class);

    // Batch upsert: INSERT ... ON CONFLICT ... DO UPDATE
    // This replaces the individual SELECT + INSERT/UPDATE pattern (25M queries → 5K queries)
    private static final String UPSERT_SQL = """
        INSERT INTO vulnerabilities (
            cve, agent_id, agent_name, agent_group, package_name, package_version,
            severity, cvss3_score, title, description, detection_time,
            status, last_sync, resolved_at
        ) VALUES (
            :cve, :agentId, :agentName, :agentGroup, :packageName, :packageVersion,
            :severity, :cvss3Score, :title, :description, :detectionTime,
            'Active', :lastSync, NULL
        )
        ON CONFLICT (cve, agent_id, package_name) DO UPDATE SET
            agent_name = EXCLUDED.agent_name,
            agent_group = EXCLUDED.agent_group,
            package_version = EXCLUDED.package_version,
            severity = EXCLUDED.severity,
            cvss3_score = EXCLUDED.cvss3_score,
            title = EXCLUDED.title,
            description = EXCLUDED.description,
            detection_time = EXCLUDED.detection_time,
            status = 'Active',
            last_sync = EXCLUDED.last_sync,
            resolved_at = NULL
        """;

    private final RestTemplate restTemplate;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final VulnerabilitySnapshotRepository snapshotRepository;
    private final NamedParameterJdbcTemplate namedJdbcTemplate;
    private final Executor taskExecutor;

    @Value("${wazuh.index.vulnerabilities}")
    private String vulnIndex;

    @Value("${wazuh.index.monitoring}")
    private String monitoringIndex;

    public WazuhService(@Qualifier("wazuhRestTemplate") RestTemplate restTemplate,
                        VulnerabilityRepository vulnerabilityRepository,
                        VulnerabilitySnapshotRepository snapshotRepository,
                        NamedParameterJdbcTemplate namedJdbcTemplate,
                        @Qualifier("wazuhTaskExecutor") Executor taskExecutor) {
        this.restTemplate = restTemplate;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.snapshotRepository = snapshotRepository;
        this.namedJdbcTemplate = namedJdbcTemplate;
        this.taskExecutor = taskExecutor;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  MÉTODOS PÚBLICOS
    // ─────────────────────────────────────────────────────────────────────────

    private String currentSyncStatus = "IDLE";
    private String currentSyncError = null;

    public String getCurrentSyncStatus() {
        return currentSyncStatus;
    }

    public String getCurrentSyncError() {
        return currentSyncError;
    }

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
        
        return executeDirectly(creds, body);
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
        return executeDirectly(creds, body);
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
        return executeDirectly(creds, body);
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
        return executeDirectly(creds, body);
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
        return executeDirectly(creds, body);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  INFRAESTRUCTURA
    // ─────────────────────────────────────────────────────────────────────────

    private Map<String, Object> executeDirectly(WazuhCredentials creds, String queryBody) throws Exception {
        log.info(">>> EJECUTANDO ACCESO: Host Wazuh: {} | Usuario Wazuh: {}", 
                creds.wazuhHost(), creds.wazuhUser());

        return search(queryBody, creds);
    }

    private Map<String, Object> search(String queryBody, WazuhCredentials creds) {
        String auth = creds.wazuhUser() + ":" + creds.wazuhPassword();
        String credentials = Base64.getEncoder().encodeToString(
                auth.getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Basic " + credentials);
        headers.setContentType(MediaType.APPLICATION_JSON);

        String url = wazuhBaseUrl(creds) + "/" + vulnIndex + "/_search";

        ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                url, HttpMethod.POST, new HttpEntity<>(queryBody, headers), 
                new org.springframework.core.ParameterizedTypeReference<Map<String, Object>>() {}
        );
        
        return response.getBody();
    }

    public long getRemoteTotalCount(WazuhCredentials creds) throws Exception {
        String url = wazuhBaseUrl(creds) + "/" + vulnIndex + "/_count";
        
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
        currentSyncStatus = "RUNNING";
        currentSyncError = null;
        taskExecutor.execute(() -> {
            log.info("INICIANDO EXTRACCIÓN MASIVA PARA: {}", creds.wazuhHost());
            int pageSize = 5000;
            Object[] lastSortValues = null;
            boolean hasMore = true;
            long totalProcesados = 0;
            Map<String, SnapshotCounter> countersByAgent = new java.util.HashMap<>();

            try {
                LocalDateTime currentSyncTime = LocalDateTime.now();
                
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

                        Map<String, Object> response = search(body, creds);
                        
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
                                log.info("[{}] Progreso: {} registros...", creds.wazuhHost(), totalProcesados);
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
                    
                    log.info("FINALIZADO: {} registros guardados de {}", totalProcesados, creds.wazuhHost());
                    currentSyncStatus = "COMPLETED";
                }
            } catch (Exception e) {
                log.error("ERROR CRÍTICO EN HILO DE SINCRONIZACIÓN: ", e);
                currentSyncError = e.getMessage() != null ? e.getMessage() : "Error desconocido";
                currentSyncStatus = "ERROR";
            }
        });
    }

    private void processAndSaveBatch(List<Map<String, Object>> hits, Map<String, SnapshotCounter> countersByAgent, Map<String, String> agentGroupsDict, LocalDateTime currentSyncTime) {
        List<MapSqlParameterSource> batchArgs = new ArrayList<>();

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

                MapSqlParameterSource params = new MapSqlParameterSource();
                params.addValue("cve", cve);
                params.addValue("agentId", agentId);
                params.addValue("agentName", a.get("name"));
                params.addValue("packageName", pkgName);
                params.addValue("packageVersion", p.get("version"));
                params.addValue("severity", v.get("severity"));
                params.addValue("lastSync", currentSyncTime);

                String assignedGroup = agentGroupsDict.get(agentId);
                params.addValue("agentGroup",
                    (assignedGroup == null || assignedGroup.isBlank()) ? "default" : assignedGroup);

                Map<String, Object> scoreObj = (Map<String, Object>) v.get("score");
                params.addValue("cvss3Score",
                    (scoreObj != null && scoreObj.get("base") != null)
                        ? Double.valueOf(scoreObj.get("base").toString()) : null);

                params.addValue("title", v.get("title"));
                params.addValue("description", v.get("description"));

                Object detectedAt = v.get("detected_at");
                params.addValue("detectionTime", parseDetectionTime(detectedAt));

                batchArgs.add(params);
            } catch (Exception e) {
                log.warn("Hit malformado omitido: {}", e.getMessage());
            }
        }

        if (!batchArgs.isEmpty()) {
            namedJdbcTemplate.batchUpdate(UPSERT_SQL, batchArgs.toArray(new MapSqlParameterSource[0]));
        }
    }

    private LocalDateTime parseDetectionTime(Object detectedAt) {
        if (detectedAt == null) return null;
        try {
            if (detectedAt instanceof Number num) {
                long ms = num.longValue();
                if (ms > 1_000_000_000_000L)
                    return Instant.ofEpochMilli(ms).atZone(java.time.ZoneId.systemDefault()).toLocalDateTime();
                else
                    return Instant.ofEpochSecond(ms).atZone(java.time.ZoneId.systemDefault()).toLocalDateTime();
            } else {
                String s = detectedAt.toString();
                if (!s.isBlank())
                    return ZonedDateTime.parse(s).toLocalDateTime();
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private String wazuhBaseUrl(WazuhCredentials creds) {
        return "https://" + creds.wazuhHost() + ":9200";
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
            String url = wazuhBaseUrl(creds) + "/" + monitoringIndex + "/_search";

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
