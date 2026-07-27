-- V4: Desnormalización de vulnerability_timeline_events para acelerar búsquedas
-- Añadimos columnas usadas en los filtros de la línea de tiempo.

ALTER TABLE vulnerability_timeline_events 
    ADD COLUMN agent_name VARCHAR(255),
    ADD COLUMN cvss3_score DOUBLE PRECISION,
    ADD COLUMN package_name VARCHAR(255),
    ADD COLUMN status VARCHAR(50),
    ADD COLUMN detection_time TIMESTAMP;

-- Actualizamos los registros existentes (Backfill)
UPDATE vulnerability_timeline_events t
SET 
    agent_name = v.agent_name,
    cvss3_score = v.cvss3_score,
    package_name = v.package_name,
    status = v.status,
    detection_time = v.detection_time
FROM vulnerabilities v
WHERE t.vulnerability_id = v.id;

-- Índices para optimizar los filtros comunes
CREATE INDEX IF NOT EXISTS idx_tle_agent_name ON vulnerability_timeline_events (agent_name);
CREATE INDEX IF NOT EXISTS idx_tle_cvss3_score ON vulnerability_timeline_events (cvss3_score);
CREATE INDEX IF NOT EXISTS idx_tle_package_name ON vulnerability_timeline_events (package_name);
CREATE INDEX IF NOT EXISTS idx_tle_status ON vulnerability_timeline_events (status);
CREATE INDEX IF NOT EXISTS idx_tle_detection_time ON vulnerability_timeline_events (detection_time);

-- Índice combinado para acelerar la deduplicación del popover
CREATE INDEX IF NOT EXISTS idx_tle_cve_agent_name ON vulnerability_timeline_events (cve, agent_name);
