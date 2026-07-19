package com.devsecops.vulncheckerbackend.services;

import com.devsecops.vulncheckerbackend.dto.TimelinePointDto;
import com.devsecops.vulncheckerbackend.dto.TimelineVulnItemDto;
import com.devsecops.vulncheckerbackend.entities.VulnerabilityTimelineEventEntity;
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
     * @param months          cantidad de puntos a retornar (máx 12)
     * @param cve             filtrar por CVE (LIKE)
     * @param severity        filtrar por severidad exacta
     * @param agentId         filtrar por agente exacto
     * @param highPriorityOnly solo critical y high
     * @param search          búsqueda general aplicada sobre cve
     */
    public List<TimelinePointDto> getTimeline(
            int months,
            String cve,
            String severity,
            String agentId,
            boolean highPriorityOnly,
            String search
    ) {
        int safeMonths = Math.max(1, Math.min(months, MAX_MONTHS));

        // Normalización: null si blank para las queries nativas
        String normCve      = normalize(cve);
        String normSeverity = normalize(severity);
        String normAgentId  = normalize(agentId);
        String normSearch   = normalize(search);

        // Obtener las últimas N fechas distintas (vienen DESC, las invertimos para mostrar cronológicamente)
        List<LocalDate> dates = timelineRepo.findDistinctSyncDatesDesc(safeMonths);
        if (dates.isEmpty()) {
            return Collections.emptyList();
        }

        // Invertir para orden cronológico ascendente (izquierda → derecha en el timeline)
        List<LocalDate> chronological = new ArrayList<>(dates);
        Collections.reverse(chronological);

        List<TimelinePointDto> points = new ArrayList<>(chronological.size());

        for (LocalDate date : chronological) {
            int newCount = timelineRepo.countByDateAndType(
                    date, "NEW", normCve, normSeverity, normAgentId, highPriorityOnly, normSearch);
            int resolvedCount = timelineRepo.countByDateAndType(
                    date, "RESOLVED", normCve, normSeverity, normAgentId, highPriorityOnly, normSearch);

            List<VulnerabilityTimelineEventEntity> newEntities = timelineRepo.findByDateAndType(
                    date, "NEW", normCve, normSeverity, normAgentId, highPriorityOnly, normSearch);
            List<VulnerabilityTimelineEventEntity> resolvedEntities = timelineRepo.findByDateAndType(
                    date, "RESOLVED", normCve, normSeverity, normAgentId, highPriorityOnly, normSearch);

            List<TimelineVulnItemDto> newVulns = newEntities.stream()
                    .map(e -> new TimelineVulnItemDto(e.getCve(), e.getSeverity(), e.getAgentId()))
                    .toList();
            List<TimelineVulnItemDto> resolvedVulns = resolvedEntities.stream()
                    .map(e -> new TimelineVulnItemDto(e.getCve(), e.getSeverity(), e.getAgentId()))
                    .toList();

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
                (sync_date, vulnerability_id, cve, severity, agent_id, event_type)
            SELECT first_seen_sync, id, cve, severity, agent_id, 'NEW'
            FROM   vulnerabilities
            WHERE  first_seen_sync IS NOT NULL
            ON CONFLICT DO NOTHING
            """;
        int newEvents = jdbcTemplate.update(insertNew, new MapSqlParameterSource());
        log.info("Backfill: {} eventos NEW insertados.", newEvents);

        // 3. Insertar eventos RESOLVED
        String insertResolved = """
            INSERT INTO vulnerability_timeline_events
                (sync_date, vulnerability_id, cve, severity, agent_id, event_type)
            SELECT DATE(resolved_at), id, cve, severity, agent_id, 'RESOLVED'
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
}
