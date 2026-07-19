-- V3: Timeline events pre-calculation
-- Adds first_seen_sync to vulnerabilities (set only on first INSERT via COALESCE in upsert)
-- Creates vulnerability_timeline_events for fast timeline queries

-- 1. Nueva columna en vulnerabilities: fecha de primera aparición
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS first_seen_sync DATE;

-- Índice para llenado eficiente de timeline_events al hacer saveTimelineEvents()
CREATE INDEX IF NOT EXISTS idx_vuln_first_seen_sync
    ON vulnerabilities (first_seen_sync);

-- Índice para sweep: buscar resueltas por fecha de resolved_at
CREATE INDEX IF NOT EXISTS idx_vuln_resolved_at_date
    ON vulnerabilities ((resolved_at::date));

-- 2. Tabla pre-calculada de eventos del timeline
CREATE TABLE IF NOT EXISTS vulnerability_timeline_events (
    id               BIGSERIAL    PRIMARY KEY,
    sync_date        DATE         NOT NULL,
    vulnerability_id BIGINT       NOT NULL,
    cve              VARCHAR(50)  NOT NULL,
    severity         VARCHAR(20),
    agent_id         VARCHAR(50),
    event_type       VARCHAR(10)  NOT NULL  -- 'NEW' o 'RESOLVED'
);

-- Índices para queries del endpoint GET /api/timeline con filtros
CREATE INDEX IF NOT EXISTS idx_tle_sync_date
    ON vulnerability_timeline_events (sync_date DESC);

CREATE INDEX IF NOT EXISTS idx_tle_cve
    ON vulnerability_timeline_events (cve);

CREATE INDEX IF NOT EXISTS idx_tle_severity
    ON vulnerability_timeline_events (severity);

CREATE INDEX IF NOT EXISTS idx_tle_type_date
    ON vulnerability_timeline_events (event_type, sync_date);

CREATE INDEX IF NOT EXISTS idx_tle_agent
    ON vulnerability_timeline_events (agent_id);
