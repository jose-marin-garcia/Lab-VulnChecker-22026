-- flyway:no-transaction
-- V5: Convertir vulnerability_timeline_events en hypertable y crear Continuous Aggregate

-- 1. Modificar la clave primaria para incluir la columna de partición (sync_date)
ALTER TABLE vulnerability_timeline_events DROP CONSTRAINT IF EXISTS vulnerability_timeline_events_pkey;
ALTER TABLE vulnerability_timeline_events ADD PRIMARY KEY (id, sync_date);

-- 2. Convertir la tabla en hypertable particionada por sync_date con intervalo de 1 mes
SELECT create_hypertable('vulnerability_timeline_events', 'sync_date',
    chunk_time_interval => INTERVAL '1 month',
    if_not_exists => TRUE,
    migrate_data => TRUE);

-- 3. Crear la vista agregada continua (Continuous Aggregate)
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_timeline_monthly_cagg
WITH (timescaledb.continuous) AS
SELECT 
    time_bucket(INTERVAL '1 month', sync_date) AS bucket,
    event_type,
    severity,
    agent_name,
    package_name,
    status,
    cvss3_score,
    detection_time::date AS detection_date,
    cve
FROM vulnerability_timeline_events
GROUP BY bucket, event_type, severity, agent_name, package_name, status, cvss3_score, detection_date, cve
WITH NO DATA;
