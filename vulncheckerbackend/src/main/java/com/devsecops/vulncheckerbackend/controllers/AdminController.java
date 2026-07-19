package com.devsecops.vulncheckerbackend.controllers;

import com.devsecops.vulncheckerbackend.services.TimelineService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Operaciones de administración del sistema.
 * Sólo debe ser accedida por usuarios con rol ADMIN.
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private static final Logger log = LoggerFactory.getLogger(AdminController.class);
    private final TimelineService timelineService;

    public AdminController(TimelineService timelineService) {
        this.timelineService = timelineService;
    }

    /**
     * Rellena la tabla vulnerability_timeline_events a partir de los datos
     * ya existentes en vulnerabilities.
     *
     * Útil cuando:
     *  - Se actualiza el sistema con el nuevo módulo de Timeline y ya hay datos históricos.
     *  - La tabla timeline_events queda desincronizada por algún error.
     *
     * Es idempotente: usa INSERT ... ON CONFLICT DO NOTHING para no duplicar eventos.
     */
    @PostMapping("/timeline/backfill")
    public ResponseEntity<Map<String, Object>> backfillTimeline() {
        log.info(">>> Admin: iniciando backfill de vulnerability_timeline_events...");
        Map<String, Object> result = timelineService.backfillFromExistingData();
        log.info(">>> Admin: backfill completado. Resultado: {}", result);
        return ResponseEntity.ok(result);
    }
}
