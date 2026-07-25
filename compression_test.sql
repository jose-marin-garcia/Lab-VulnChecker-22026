-- =============================================
-- TEST DE COMPRESIÓN TimescaleDB
-- Mide espacio ANTES y DESPUÉS de comprimir
-- =============================================

-- =============================================
-- PASO 1: Insertar datos de prueba (~500K vulns)
-- =============================================
SELECT '--- INSERTANDO DATOS ---' AS section;

DO $$
DECLARE
    i INT;
    severities TEXT[] := ARRAY['Critical', 'High', 'Medium', 'Low'];
    statuses TEXT[] := ARRAY['Active', 'Resolved'];
    base_date TIMESTAMP;
BEGIN
    FOR i IN 1..500000 LOOP
        base_date := '2024-01-01'::timestamp +
            (random() * 180 * INTERVAL '1 day');

        INSERT INTO vulnerabilities (
            cve, agent_id, agent_name, severity, cvss3_score,
            package_name, package_version, description, title,
            status, detection_time, last_sync, agent_group
        ) VALUES (
            'CVE-2024-' || LPAD((10000 + (i % 90000))::TEXT, 5, '0'),
            (1000 + (i % 300))::TEXT,
            'agent-' || (1000 + (i % 300))::TEXT,
            severities[1 + (i % 4)],
            (random() * 10)::NUMERIC(3,1),
            'package-' || (i % 500),
            '1.0.' || (i % 100),
            'Description for vulnerability ' || i,
            'Title for CVE-' || i,
            statuses[1 + (i % 2)],
            base_date,
            NOW() - (random() * 30 * INTERVAL '1 day'),
            'group-' || (i % 10)
        );

        IF i % 10000 = 0 THEN
            COMMIT;
            RAISE NOTICE 'Insertadas % filas...', i;
        END IF;
    END LOOP;
END $$;

-- =============================================
-- PASO 2: Verificar chunks
-- =============================================
SELECT '--- CHUNKS CREADOS ---' AS section;

SELECT COUNT(*) AS total_chunks,
       COUNT(*) FILTER (WHERE is_compressed = TRUE) AS comprimidos,
       COUNT(*) FILTER (WHERE is_compressed = FALSE) AS sin_comprimir
FROM timescaledb_information.chunks
WHERE hypertable_name = 'vulnerabilities';

SELECT chunk_name,
       pg_size_pretty(pg_total_relation_size(format('%I.%I', chunk_schema, chunk_name)::regclass)) AS tamaño,
       range_start::date AS inicio
FROM timescaledb_information.chunks
WHERE hypertable_name = 'vulnerabilities'
ORDER BY range_start;

-- =============================================
-- PASO 3: Espacio ANTES de compresión
-- =============================================
SELECT '--- ESPACIO ANTES DE COMPRIMIR ---' AS section;

SELECT
    pg_size_pretty(
        (SELECT pg_total_relation_size(format('%I.%I', hypertable_schema, hypertable_name)::regclass)
         FROM timescaledb_information.hypertables WHERE hypertable_name = 'vulnerabilities')
        +
        (SELECT COALESCE(SUM(pg_total_relation_size(format('%I.%I', chunk_schema, chunk_name)::regclass)), 0)
         FROM timescaledb_information.chunks WHERE hypertable_name = 'vulnerabilities')
    ) AS total_antes;

-- =============================================
-- PASO 4: Comprimir todos los chunks
-- =============================================
SELECT '--- COMPRIMIENDO CHUNKS ---' AS section;

DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN
        SELECT chunk_name, chunk_schema
        FROM timescaledb_information.chunks
        WHERE hypertable_name = 'vulnerabilities'
            AND is_compressed = FALSE
    LOOP
        BEGIN
            PERFORM compress_chunk(format('%I.%I', r.chunk_schema, r.chunk_name)::regclass);
            RAISE NOTICE 'Comprimido: %', r.chunk_name;
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'No se pudo comprimir %: %', r.chunk_name, SQLERRM;
        END;
    END LOOP;
END $$;

-- =============================================
-- PASO 5: Espacio DESPUÉS de compresión
-- =============================================
SELECT '--- ESPACIO DESPUÉS DE COMPRIMIR ---' AS section;

SELECT
    pg_size_pretty(
        (SELECT pg_total_relation_size(format('%I.%I', hypertable_schema, hypertable_name)::regclass)
         FROM timescaledb_information.hypertables WHERE hypertable_name = 'vulnerabilities')
        +
        (SELECT COALESCE(SUM(pg_total_relation_size(format('%I.%I', chunk_schema, chunk_name)::regclass)), 0)
         FROM timescaledb_information.chunks WHERE hypertable_name = 'vulnerabilities')
    ) AS total_despues;

-- =============================================
-- PASO 6: Detalle por chunk
-- =============================================
SELECT '--- DETALLE POR CHUNK ---' AS section;

SELECT chunk_name,
       is_compressed,
       pg_size_pretty(pg_total_relation_size(format('%I.%I', chunk_schema, chunk_name)::regclass)) AS tamaño,
       range_start::date AS inicio
FROM timescaledb_information.chunks
WHERE hypertable_name = 'vulnerabilities'
ORDER BY range_start;

-- =============================================
-- PASO 7: Ahorro final
-- =============================================
SELECT '--- AHORRO ---' AS section;

SELECT
    pg_size_pretty(
        (SELECT pg_total_relation_size(format('%I.%I', hypertable_schema, hypertable_name)::regclass)
         FROM timescaledb_information.hypertables WHERE hypertable_name = 'vulnerabilities')
        +
        (SELECT COALESCE(SUM(pg_total_relation_size(format('%I.%I', chunk_schema, chunk_name)::regclass)), 0)
         FROM timescaledb_information.chunks WHERE hypertable_name = 'vulnerabilities')
    ) AS espacio_final,
    (SELECT COUNT(*) FROM timescaledb_information.chunks
     WHERE hypertable_name = 'vulnerabilities' AND is_compressed = TRUE) AS chunks_comprimidos,
    (SELECT COUNT(*) FROM timescaledb_information.chunks
     WHERE hypertable_name = 'vulnerabilities') AS total_chunks;

SELECT '--- LISTO ---' AS section;
