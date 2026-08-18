-- =============================================================================
-- STRESS + COMPRESSION TEST: 5,000,000 vulnerabilities
-- Para la base de datos VulnChecker (TimescaleDB)
--
-- Objetivos:
--   1. Cargar 5,000,000 de vulnerabilidades con agentes inventados para
--      demostrar que la base soporta volumen masivo sin caerse.
--   2. Verificar que los datos quedan visibles en el dashboard (métricas,
--      gráficos de torta y tabla "Vulnerabilidades por Agente").
--   3. Comprimir los chunks y mostrar el ahorro de espacio logrado.
--
-- Uso:
--   docker exec -i vuln-db psql -U admin -d vulncheck < stress_test.sql
--   (o bien: \i stress_test.sql dentro de una sesión psql al contenedor)
--
-- NOTA: el script agrega 5M de filas SIN borrar los datos existentes.
-- =============================================================================

\timing on
\set ON_ERROR_STOP off

-- =============================================================================
-- SECCIÓN 0: LIMPIEZA DE DATOS DE PRUEBA PREVIOS
-- Borra datos 'stress' previos para que cada corrida inserte SIEMPRE 5M
-- exactos (sin duplicar). Comenta para acumular corridas.
-- =============================================================================
DELETE FROM vulnerabilities WHERE agent_group = 'stress';

-- =============================================================================
-- SECCIÓN 1: CARGA MASIVA (5,000,000 filas)
-- =============================================================================
SELECT '=== PASO 1: CARGANDO 5,000,000 VULNERABILIDADES ===' AS seccion;

-- Se insertan 5,000,000 de filas repartidas en 10 agentes inventados.
-- detection_time se genera ESTRICTAMENTE único y monótono por fila
-- (base hace 365 días + 6.3 s por fila), garantizando que nunca haya
-- colisiones en el índice único (cve, agent_id, package_name, detection_time)
-- y que se inserten exactamente los 5,000,000.
INSERT INTO vulnerabilities (
    cve, agent_id, agent_name, agent_group, severity, cvss3_score,
    package_name, package_version, title, description,
    status, detection_time, last_sync, resolved_at
)
SELECT
    'CVE-2026-' || LPAD(((g % 90000) + 1)::text, 5, '0') AS cve,
    'ST-00' || ((g % 10) + 1)::text AS agent_id,
    'Agent-Stress-' || ((g % 10) + 1)::text AS agent_name,
    'stress' AS agent_group,
    CASE
        WHEN (g % 100) < 5  THEN 'Critical'
        WHEN (g % 100) < 20 THEN 'High'
        WHEN (g % 100) < 60 THEN 'Medium'
        ELSE 'Low'
    END AS severity,
    CASE
        WHEN (g % 100) < 5  THEN 9.0 + (random() * 1.0)
        WHEN (g % 100) < 20 THEN 7.0 + (random() * 1.9)
        WHEN (g % 100) < 60 THEN 4.0 + (random() * 2.9)
        ELSE 0.1 + (random() * 3.9)
    END::numeric(3,1) AS cvss3_score,
    (ARRAY['openssl', 'linux-kernel', 'curl', 'sudo', 'systemd',
           'openssh', 'glibc', 'bash', 'nginx', 'postgresql',
           'python3', 'nodejs', 'java-17-openjdk', 'vim', 'git',
           'docker.io', 'kubernetes', 'redis', 'mysql', 'mongodb'])[1 + (g % 20)] AS package_name,
    (floor(random() * 10) + 1)::text || '.' ||
    (floor(random() * 20))::text || '.' ||
    (floor(random() * 50))::text AS package_version,
    'Vulnerabilidad de prueba masiva en paquete ' || ((g % 20) + 1)::text AS title,
    'Fila generada por stress_test.sql para validar rendimiento y compresion. ' ||
    'Identificador interno ' || g::text || '.' AS description,
    CASE WHEN (g % 100) < 85 THEN 'Active' ELSE 'Resolved' END AS status,
    NOW() - INTERVAL '365 days' + (g - 1) * INTERVAL '6.3 seconds' AS detection_time,
    NOW() - (floor(random() * 30) || ' days')::interval AS last_sync,
    CASE WHEN (g % 100) >= 85
        THEN NOW() - (floor(random() * 60) || ' days')::interval
    END AS resolved_at
FROM generate_series(1, 5000000) AS g
ON CONFLICT (cve, agent_id, package_name, detection_time) DO NOTHING;

-- =============================================================================
-- SECCIÓN 2: VERIFICACIÓN DE QUE LA BD RESISTIÓ EL VOLUMEN
-- =============================================================================
SELECT '=== PASO 2: VERIFICACION DE VOLUMEN ===' AS seccion;

SELECT COUNT(*) AS total_vulnerabilidades FROM vulnerabilities;

SELECT COUNT(*) AS filas_de_prueba
FROM vulnerabilities
WHERE agent_group = 'stress';

-- Distribución por severidad (lo que alimenta el gráfico de torta)
SELECT severity, COUNT(*) AS cantidad,
       ROUND(COUNT(*) * 100.0 / NULLIF((SELECT COUNT(*) FROM vulnerabilities WHERE agent_group = 'stress'), 0), 1) AS pct
FROM vulnerabilities
WHERE agent_group = 'stress'
GROUP BY severity
ORDER BY CASE severity
    WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
    WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 END;

-- Distribución por agente (lo que alimenta la tabla "Vulnerabilidades por Agente")
SELECT agent_id, agent_name, COUNT(*) AS vulnerabilidades
FROM vulnerabilities
WHERE agent_group = 'stress'
GROUP BY agent_id, agent_name
ORDER BY vulnerabilidades DESC;

-- =============================================================================
-- SECCIÓN 3: BENCHMARK DE CONSULTAS DEL DASHBOARD (con datos masivos)
-- =============================================================================
SELECT '=== PASO 3: BENCHMARK DE CONSULTAS DEL DASHBOARD ===' AS seccion;

EXPLAIN ANALYZE
SELECT LOWER(TRIM(COALESCE(severity, ''))) AS name, COUNT(*) AS value
FROM vulnerabilities v
WHERE 1=1
GROUP BY name
ORDER BY CASE name
    WHEN 'critical' THEN 1 WHEN 'high' THEN 2
    WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END;

EXPLAIN ANALYZE
SELECT COALESCE(NULLIF(TRIM(agent_name), ''), NULLIF(TRIM(agent_id), ''), 'Sin dato') AS name,
       COUNT(*) AS value
FROM vulnerabilities v
WHERE 1=1
GROUP BY name
ORDER BY value DESC, name ASC
LIMIT 50;

EXPLAIN ANALYZE
SELECT id FROM vulnerabilities
WHERE cve = 'CVE-2026-50000' AND agent_id = 'ST-001' AND package_name = 'openssl';

-- =============================================================================
-- SECCIÓN 4: ESTADO DE CHUNKS Y ESPACIO ANTES DE COMPRIMIR
-- =============================================================================
SELECT '=== PASO 4: CHUNKS Y ESPACIO ANTES DE COMPRIMIR ===' AS seccion;

SELECT COUNT(*) AS total_chunks,
       COUNT(*) FILTER (WHERE is_compressed = TRUE) AS comprimidos,
       COUNT(*) FILTER (WHERE is_compressed = FALSE) AS sin_comprimir
FROM timescaledb_information.chunks
WHERE hypertable_name = 'vulnerabilities';

-- Espacio ocupado por los chunks ANTES de comprimir (todos sin comprimir).
SELECT pg_size_pretty(
    (SELECT COALESCE(SUM(pg_total_relation_size(format('%I.%I', c.schema_name, c.table_name)::regclass)), 0)
     FROM _timescaledb_catalog.chunk c
     JOIN _timescaledb_catalog.hypertable h ON h.id = c.hypertable_id
     WHERE h.table_name = 'vulnerabilities' AND c.compressed_chunk_id IS NULL)
) AS espacio_chunks_antes;

-- =============================================================================
-- SECCIÓN 5: COMPRIMIR CHUNKS
-- =============================================================================
SELECT '=== PASO 5: COMPRIMIENDO CHUNKS ===' AS seccion;

DO $$
DECLARE
    r RECORD;
    n INT := 0;
BEGIN
    FOR r IN
        SELECT chunk_name, chunk_schema
        FROM timescaledb_information.chunks
        WHERE hypertable_name = 'vulnerabilities'
            AND is_compressed = FALSE
    LOOP
        BEGIN
            PERFORM compress_chunk(
                format('%I.%I', r.chunk_schema, r.chunk_name)::regclass,
                if_not_compressed => TRUE
            );
            n := n + 1;
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'No se pudo comprimir %: %', r.chunk_name, SQLERRM;
        END;
    END LOOP;
    RAISE NOTICE 'Chunks comprimidos: %', n;
END $$;

-- =============================================================================
-- SECCIÓN 6: ESPACIO DESPUÉS DE COMPRIMIR Y AHORRO
-- =============================================================================
SELECT '=== PASO 6: ESPACIO DESPUÉS Y AHORRO ===' AS seccion;

-- Espacio real de los chunks comprimidos (relaciones _compressed_*).
SELECT pg_size_pretty(
    (SELECT COALESCE(SUM(pg_total_relation_size(format('%I.%I', cc.schema_name, cc.table_name)::regclass)), 0)
     FROM _timescaledb_catalog.chunk c
     JOIN _timescaledb_catalog.chunk cc ON cc.id = c.compressed_chunk_id
     JOIN _timescaledb_catalog.hypertable h ON h.id = c.hypertable_id
     WHERE h.table_name = 'vulnerabilities')
) AS espacio_chunks_despues;

-- Resumen: chunks, comprimidos y ratio de ahorro.
WITH antes AS (
    SELECT COALESCE(SUM(pg_total_relation_size(format('%I.%I', c.schema_name, c.table_name)::regclass)), 0) AS bytes
    FROM _timescaledb_catalog.chunk c
    JOIN _timescaledb_catalog.hypertable h ON h.id = c.hypertable_id
    WHERE h.table_name = 'vulnerabilities' AND c.compressed_chunk_id IS NULL
),
despues AS (
    SELECT COALESCE(SUM(pg_total_relation_size(format('%I.%I', cc.schema_name, cc.table_name)::regclass)), 0) AS bytes
    FROM _timescaledb_catalog.chunk c
    JOIN _timescaledb_catalog.chunk cc ON cc.id = c.compressed_chunk_id
    JOIN _timescaledb_catalog.hypertable h ON h.id = c.hypertable_id
    WHERE h.table_name = 'vulnerabilities'
)
SELECT
    pg_size_pretty(a.bytes) AS antes,
    pg_size_pretty(d.bytes) AS despues,
    ROUND((1 - d.bytes::numeric / NULLIF(a.bytes, 0)) * 100, 1) AS ahorro_pct,
    (SELECT COUNT(*) FROM timescaledb_information.chunks
     WHERE hypertable_name = 'vulnerabilities' AND is_compressed = TRUE) AS chunks_comprimidos,
    (SELECT COUNT(*) FROM timescaledb_information.chunks
     WHERE hypertable_name = 'vulnerabilities') AS total_chunks
FROM antes a, despues d;

SELECT '=== VERIFICACION FINAL: LOS DATOS SIGUEN ACCESIBLES ===' AS seccion;

SELECT COUNT(*) AS total_vulnerabilidades FROM vulnerabilities;

SELECT agent_id, agent_name, COUNT(*) AS vulnerabilidades
FROM vulnerabilities
WHERE agent_group = 'stress'
GROUP BY agent_id, agent_name
ORDER BY vulnerabilidades DESC
LIMIT 10;

-- =============================================================================
-- LIMPIEZA FINAL: borra los datos de prueba y deja solo los reales de Wazuh.
-- (La Sección 0 ya limpia al inicio de cada corrida; este es por si querés
--  revertir la carga sin volver a correr el script completo.)
-- DELETE FROM vulnerabilities WHERE agent_group = 'stress';
-- =============================================================================
SELECT '=== STRESS + COMPRESSION TEST COMPLETADO ===' AS seccion;
