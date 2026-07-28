package com.devsecops.vulncheckerbackend.services;

import com.devsecops.vulncheckerbackend.dto.TimelinePointDto;
import com.devsecops.vulncheckerbackend.dto.TimelineVulnItemDto;
import com.devsecops.vulncheckerbackend.repositories.VulnerabilityTimelineEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

@Service
public class TimelineService {

    private static final Logger log = LoggerFactory.getLogger(TimelineService.class);

    private static final int MAX_MONTHS = 12;
    private static final DateTimeFormatter LABEL_FORMAT =
            DateTimeFormatter.ofPattern("MMM dd", Locale.forLanguageTag("es-CL"));
    private static final DateTimeFormatter KEY_FORMAT = DateTimeFormatter.ISO_LOCAL_DATE;

    private final VulnerabilityTimelineEventRepository timelineRepo;
    private final NamedParameterJdbcTemplate jdbcTemplate;

    public TimelineService(VulnerabilityTimelineEventRepository timelineRepo,
                           NamedParameterJdbcTemplate jdbcTemplate) {
        this.timelineRepo = timelineRepo;
        this.jdbcTemplate  = jdbcTemplate;
    }

    /**
     * Retorna los últimos N puntos del timeline con sus conteos y listas de vulns.
     * Todos los filtros son opcionales (null o blank = sin filtro).
     *
     * Optimización: usa 3 queries en total (fechas + conteos agrupados + detalles)
     * en vez del antiguo bucle N×4 queries por fecha.
     */
    public List<TimelinePointDto> getTimeline(
            int months,
            String cve,
            String severity,
            String agentName,
            boolean highPriorityOnly,
            String search,
            Double minCvss,
            Double maxCvss,
            String packageName,
            String status,
            String startDate,
            String endDate
    ) {
        int safeMonths = Math.max(1, Math.min(months, MAX_MONTHS));

        // ── Query 1: obtener las últimas N fechas distintas ──────────────────
        List<LocalDate> dates = timelineRepo.findDistinctSyncDatesDesc(safeMonths);
        if (dates.isEmpty()) {
            return Collections.emptyList();
        }

        // Invertir para orden cronológico ascendente
        List<LocalDate> chronological = new ArrayList<>(dates);
        Collections.reverse(chronological);

        // ── Normalización de filtros ─────────────────────────────────────────
        String normCve      = normalize(cve);
        String normSeverity = normalize(severity);
        String normAgentName  = normalize(agentName);
        String normSearch   = normalize(search);
        String normPackage  = normalize(packageName);
        String normStatus   = normalize(status);
        Double normMinCvss  = (minCvss != null && minCvss > 0)  ? minCvss : null;
        Double normMaxCvss  = (maxCvss != null && maxCvss < 10) ? maxCvss : null;
        LocalDate normStartDate = parseDate(startDate);
        LocalDate normEndDate   = parseDate(endDate);

        // Mapear sync_dates a sus respectivos buckets de inicio de mes
        List<LocalDate> buckets = new ArrayList<>();
        for (LocalDate date : chronological) {
            buckets.add(date.withDayOfMonth(1));
        }

        // Cláusula WHERE compartida por las dos queries de datos sobre mv_timeline_monthly_cagg
        String sharedWhere = """
              t.bucket IN (:buckets)
          AND (:cve       IS NULL OR LOWER(t.cve)      LIKE LOWER(CONCAT('%', :cve,      '%')))
          AND (:severity  IS NULL OR LOWER(t.severity)  = LOWER(:severity))
          AND (:agentName IS NULL OR t.agent_name       = :agentName)
          AND (:highPrio  = FALSE
               OR LOWER(t.severity) IN ('critical','high','crítica','critica','alta'))
          AND (:search    IS NULL OR LOWER(t.cve)       LIKE LOWER(CONCAT('%', :search,   '%')))
          AND (:minCvss   IS NULL OR t.cvss3_score      >= CAST(:minCvss AS double precision))
          AND (:maxCvss   IS NULL OR t.cvss3_score      <= CAST(:maxCvss AS double precision))
          AND (:pkg       IS NULL OR LOWER(t.package_name) LIKE LOWER(CONCAT('%', :pkg, '%')))
          AND (:status    IS NULL OR LOWER(t.status)    = LOWER(:status))
          AND (CAST(:startDt AS date) IS NULL OR t.detection_date >= CAST(:startDt AS date))
          AND (CAST(:endDt   AS date) IS NULL OR t.detection_date <= (CAST(:endDt AS date) + INTERVAL '1 day'))
        """;

        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("buckets",   buckets)
                .addValue("cve",      normCve,      java.sql.Types.VARCHAR)
                .addValue("severity", normSeverity,  java.sql.Types.VARCHAR)
                .addValue("agentName", normAgentName, java.sql.Types.VARCHAR)
                .addValue("highPrio", highPriorityOnly)
                .addValue("search",   normSearch,    java.sql.Types.VARCHAR)
                .addValue("minCvss",  normMinCvss,   java.sql.Types.DOUBLE)
                .addValue("maxCvss",  normMaxCvss,   java.sql.Types.DOUBLE)
                .addValue("pkg",      normPackage,   java.sql.Types.VARCHAR)
                .addValue("status",   normStatus,    java.sql.Types.VARCHAR)
                .addValue("startDt",  normStartDate, java.sql.Types.DATE)
                .addValue("endDt",    normEndDate,   java.sql.Types.DATE);

        // ── Query 2: conteos agrupados por (bucket, event_type) ───────────
        String countSql = """
            SELECT t.bucket, t.event_type, COUNT(DISTINCT t.cve) AS cnt
            FROM mv_timeline_monthly_cagg t
            WHERE """ + sharedWhere + """
            GROUP BY t.bucket, t.event_type
        """;

        // Mapa: "2026-07-01|NEW" → 42
        Map<String, Integer> countMap = new java.util.HashMap<>();
        jdbcTemplate.query(countSql, params, (rs) -> {
            String key = rs.getDate("bucket").toLocalDate() + "|" + rs.getString("event_type");
            countMap.put(key, rs.getInt("cnt"));
        });

        // ── Query 3: detalles para el popover (máx 50 por grupo) ─────────────
        // Usa ROW_NUMBER() para limitar a 50 registros por (bucket, event_type)
        String detailSql = """
            SELECT bucket, event_type, cve, severity, agent_name
            FROM (
                SELECT bucket, event_type, cve, severity, agent_name,
                       ROW_NUMBER() OVER (
                           PARTITION BY bucket, event_type
                           ORDER BY severity, cve
                       ) AS rn
                FROM (
                    SELECT DISTINCT t.bucket, t.event_type, t.cve, t.severity, t.agent_name
                    FROM mv_timeline_monthly_cagg t
                    WHERE """ + sharedWhere + """
                ) dist
            ) ranked
            WHERE rn <= 50
            ORDER BY bucket, event_type, severity, cve
        """;

        Map<String, List<TimelineVulnItemDto>> detailMap = new java.util.HashMap<>();
        jdbcTemplate.query(detailSql, params, (rs) -> {
            String key = rs.getDate("bucket").toLocalDate() + "|" + rs.getString("event_type");
            detailMap
                    .computeIfAbsent(key, k -> new ArrayList<>())
                    .add(new TimelineVulnItemDto(
                            rs.getString("cve"),
                            rs.getString("severity"),
                            rs.getString("agent_name")
                    ));
        });

        // ── Ensamblar la respuesta ───────────────────────────────────────────
        List<TimelinePointDto> points = new ArrayList<>(chronological.size());

        for (LocalDate date : chronological) {
            String bucketStr   = date.withDayOfMonth(1).toString();
            String newKey      = bucketStr + "|NEW";
            String resolvedKey = bucketStr + "|RESOLVED";

            int newCount      = countMap.getOrDefault(newKey,      0);
            int resolvedCount = countMap.getOrDefault(resolvedKey, 0);

            List<TimelineVulnItemDto> newVulns      = detailMap.getOrDefault(newKey,      Collections.emptyList());
            List<TimelineVulnItemDto> resolvedVulns = detailMap.getOrDefault(resolvedKey, Collections.emptyList());

            String label = capitalize(LABEL_FORMAT.format(date));

            points.add(new TimelinePointDto(
                    KEY_FORMAT.format(date),
                    label,
                    newCount,
                    resolvedCount,
                    newVulns,
                    resolvedVulns
            ));
        }

        return points;
    }

    // ─── Backfill ─────────────────────────────────────────────────────────────

    /**
     * Rellena vulnerability_timeline_events y first_seen_sync a partir de los
     * datos ya existentes en la tabla vulnerabilities.
     *
     * Lógica de backfill:
     *  - first_seen_sync = DATE(last_sync) para vulns donde first_seen_sync IS NULL
     *    (la mejor aproximación disponible para datos históricos)
     *  - Eventos NEW  = vulns cuyo first_seen_sync se acaba de rellenar
     *  - Eventos RESOLVED = vulns con resolved_at NOT NULL
     *
     * Es idempotente gracias a ON CONFLICT DO NOTHING.
     */
    public Map<String, Object> backfillFromExistingData() {

        // 1. Rellenar first_seen_sync para datos históricos
        String updateFirstSeen = """
            UPDATE vulnerabilities
            SET    first_seen_sync = DATE(last_sync)
            WHERE  first_seen_sync IS NULL
            """;
        int updated = jdbcTemplate.update(updateFirstSeen, new MapSqlParameterSource());
        log.info("Backfill: {} filas con first_seen_sync actualizado.", updated);

        // 2. Insertar eventos NEW agrupados por sync_date
        //    ON CONFLICT DO NOTHING por si ya existían
        String insertNew = """
            INSERT INTO vulnerability_timeline_events
                (sync_date, vulnerability_id, cve, severity, agent_id, event_type, agent_name, cvss3_score, package_name, status, detection_time)
            SELECT first_seen_sync, id, cve, severity, agent_id, 'NEW', agent_name, cvss3_score, package_name, status, detection_time
            FROM   vulnerabilities
            WHERE  first_seen_sync IS NOT NULL
            ON CONFLICT DO NOTHING
            """;
        int newEvents = jdbcTemplate.update(insertNew, new MapSqlParameterSource());
        log.info("Backfill: {} eventos NEW insertados.", newEvents);

        // 3. Insertar eventos RESOLVED
        String insertResolved = """
            INSERT INTO vulnerability_timeline_events
                (sync_date, vulnerability_id, cve, severity, agent_id, event_type, agent_name, cvss3_score, package_name, status, detection_time)
            SELECT DATE(resolved_at), id, cve, severity, agent_id, 'RESOLVED', agent_name, cvss3_score, package_name, status, detection_time
            FROM   vulnerabilities
            WHERE  resolved_at IS NOT NULL
            ON CONFLICT DO NOTHING
            """;
        int resolvedEvents = jdbcTemplate.update(insertResolved, new MapSqlParameterSource());
        log.info("Backfill: {} eventos RESOLVED insertados.", resolvedEvents);

        return Map.of(
                "firstSeenSyncUpdated", updated,
                "newEventsInserted",    newEvents,
                "resolvedEventsInserted", resolvedEvents
        );
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    /** Retorna null si el valor es null o blank, para que las queries nativas interpreten "sin filtro". */
    private String normalize(String value) {
        if (value == null || value.isBlank() || "all".equalsIgnoreCase(value.trim())) {
            return null;
        }
        return value.trim();
    }

    private String capitalize(String value) {
        if (value == null || value.isBlank()) return "";
        String lower = value.toLowerCase(Locale.ROOT);
        return Character.toUpperCase(lower.charAt(0)) + lower.substring(1);
    }

    /** Parsea un string yyyy-MM-dd a LocalDate. Retorna null si es null, blank o inválido. */
    private LocalDate parseDate(String dateStr) {
        if (dateStr == null || dateStr.isBlank()) return null;
        try {
            return LocalDate.parse(dateStr.trim());
        } catch (Exception e) {
            log.warn("Fecha inválida recibida en timeline: {}", dateStr);
            return null;
        }
    }
}
