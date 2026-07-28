-- =============================================================
-- VULNCHECKER - BENCHMARK & SCALABILITY DASHBOARD
-- Ejecutar en psql o pgAdmin sobre la base de datos activa.
-- Genera un reporte completo de rendimiento e indices.
-- =============================================================

\echo ''
\echo '============================================================='
\echo '  VULNCHECKER - BENCHMARK & SCALABILITY DASHBOARD'
\echo '  Fecha: '
\echo '============================================================='
\echo ''

-- =============================================
-- 1. ESTADISTICAS GENERALES DE LA BASE DE DATOS
-- =============================================
\echo ''
\echo '--- [1] ESTADISTICAS GENERALES ---'
SELECT
    current_database() AS base_de_datos,
    pg_size_pretty(pg_database_size(current_database())) AS tamano_total,
    (SELECT count(*) FROM vulnerabilities) AS total_vulnerabilities,
    (SELECT count(*) FROM vulnerability_snapshots) AS total_snapshots,
    (SELECT count(*) FROM users) AS total_users,
    (SELECT count(DISTINCT agent_id) FROM vulnerabilities) AS total_agentes,
    (SELECT count(DISTINCT cve) FROM vulnerabilities) AS total_cves_unicos;

-- =============================================
-- 2. TAMANO DE TABLAS
-- =============================================
\echo ''
\echo '--- [2] TAMANO DE TABLAS ---'
SELECT
    schemaname || '.' || tablename AS tabla,
    pg_size_pretty(pg_total_relation_size(schemaname || '.' || tablename)) AS tamano_total,
    pg_size_pretty(pg_relation_size(schemaname || '.' || tablename)) AS tamano_datos,
    pg_size_pretty(pg_indexes_size(schemaname || '.' || tablename)) AS tamano_indices
FROM pg_tables
WHERE schemaname = 'public'
    AND tablename IN ('vulnerabilities', 'vulnerability_snapshots', 'users', 'report_signatures')
ORDER BY pg_total_relation_size(schemaname || '.' || tablename) DESC;

-- =============================================
-- 3. DISTRIBUCION DE SEVERIDADES
-- =============================================
\echo ''
\echo '--- [3] DISTRIBUCION DE SEVERIDADES ---'
SELECT
    COALESCE(severity, '(NULL)') AS severidad,
    count(*) AS cantidad,
    ROUND(100.0 * count(*) / (SELECT count(*) FROM vulnerabilities), 2) AS porcentaje,
    ROUND(AVG(cvss3_score)::numeric, 2) AS cvss_promedio
FROM vulnerabilities
GROUP BY severity
ORDER BY count(*) DESC;

-- =============================================
-- 4. DISTRIBUCION POR ESTADO
-- =============================================
\echo ''
\echo '--- [4] DISTRIBUCION POR ESTADO ---'
SELECT
    COALESCE(status, '(NULL)') AS estado,
    count(*) AS cantidad,
    ROUND(100.0 * count(*) / (SELECT count(*) FROM vulnerabilities), 2) AS porcentaje
FROM vulnerabilities
GROUP BY status
ORDER BY count(*) DESC;

-- =============================================
-- 5. TOP 10 AGENTES CON MAS VULNERABILIDADES
-- =============================================
\echo ''
\echo '--- [5] TOP 10 AGENTES ---'
SELECT
    COALESCE(agent_name, agent_id, '(Sin dato)') AS agente,
    agent_group AS grupo,
    count(*) AS total_vulns,
    count(*) FILTER (WHERE severity = 'Critical') AS criticas,
    count(*) FILTER (WHERE severity = 'High') AS altas,
    ROUND(AVG(cvss3_score)::numeric, 2) AS cvss_promedio
FROM vulnerabilities
GROUP BY agent_name, agent_id, agent_group
ORDER BY count(*) DESC
LIMIT 10;

-- =============================================
-- 6. TOP 10 PAQUETES MAS VULNERABLES
-- =============================================
\echo ''
\echo '--- [6] TOP 10 PAQUETES VULNERABLES ---'
SELECT
    COALESCE(package_name, '(Sin dato)') AS paquete,
    count(*) AS total_vulns,
    count(DISTINCT cve) AS cves_unicos,
    ROUND(AVG(cvss3_score)::numeric, 2) AS cvss_promedio
FROM vulnerabilities
WHERE package_name IS NOT NULL
GROUP BY package_name
ORDER BY count(*) DESC
LIMIT 10;

-- =============================================
-- 7. RANGO TEMPORAL DE DETECCION
-- =============================================
\echo ''
\echo '--- [7] RANGO TEMPORAL ---'
SELECT
    min(detection_time) AS primera_deteccion,
    max(detection_time) AS ultima_deteccion,
    max(detection_time) - min(detection_time) AS rango_total,
    count(DISTINCT date_trunc('day', detection_time)) AS dias_con_detecciones,
    count(*) / GREATEST(count(DISTINCT date_trunc('day', detection_time)), 1) AS promedio_vulns_por_dia
FROM vulnerabilities;

-- =============================================
-- 8. USO DE INDICES
-- =============================================
\echo ''
\echo '--- [8] USO DE INDICES ---'
SELECT
    schemaname || '.' || relname AS tabla,
    indexrelname AS indice,
    pg_size_pretty(pg_relation_size(indexrelid)) AS tamano,
    idx_scan AS veces_usado,
    idx_tup_read AS tuplas_leidas,
    idx_tup_fetch AS tuplas_obtenidas,
    CASE
        WHEN idx_scan = 0 THEN 'SIN USO'
        WHEN idx_scan < 10 THEN 'BAJO'
        WHEN idx_scan < 100 THEN 'MEDIO'
        ELSE 'ALTO'
    END AS nivel_uso
FROM pg_stat_user_indexes
WHERE schemaname = 'public'
    AND relname IN ('vulnerabilities', 'vulnerability_snapshots')
ORDER BY idx_scan DESC;

-- =============================================
-- 9. TAMANO Y EFICIENCIA DE INDICES
-- =============================================
\echo ''
\echo '--- [9] INDICES DETALLADOS ---'
SELECT
    indexrelname AS indice,
    pg_size_pretty(pg_relation_size(indexrelid)) AS tamano,
    idx_scan AS escaneos,
    CASE
        WHEN idx_scan = 0 THEN 'NO UTILIZADO - Candidato a eliminacion'
        WHEN pg_relation_size(indexrelid) > 10485760 AND idx_scan < 100 THEN 'PESADO Y POCO USADO - Revisar'
        ELSE 'SALUDABLE'
    END AS estado
FROM pg_stat_user_indexes
WHERE schemaname = 'public'
    AND relname = 'vulnerabilities'
ORDER BY pg_relation_size(indexrelid) DESC;

-- =============================================
-- 10. VISTAS MATERIALIZADAS - RENDIMIENTO
-- =============================================
\echo ''
\echo '--- [10] VISTAS MATERIALIZADAS ---'
SELECT
    matviewname AS vista,
    pg_size_pretty(pg_relation_size(schemaname || '.' || matviewname)) AS tamano,
    ispopulated AS poblada
FROM pg_matviews
WHERE schemaname = 'public'
ORDER BY matviewname;

-- Benchmark: Vista materializada vs consulta en vivo
\echo ''
\echo '--- [10a] BENCHMARK: Vista materializada vs DISTINCT en vivo ---'
\echo 'Probando consulta de severidades unicas...'

\echo '  [Vista Materializada] mv_vulnerabilities_severities:'
\timing on
SELECT count(*) FROM mv_vulnerabilities_severities;
\timing off

\echo '  [Consulta en Vivo] DISTINCT sobre vulnerabilities:'
\timing on
SELECT count(DISTINCT severity) FROM vulnerabilities WHERE severity IS NOT NULL;
\timing off

\echo ''
\echo 'Probando consulta de paquetes unicos...'

\echo '  [Vista Materializada] mv_vulnerabilities_packages:'
\timing on
SELECT count(*) FROM mv_vulnerabilities_packages;
\timing off

\echo '  [Consulta en Vivo] DISTINCT sobre vulnerabilities:'
\timing on
SELECT count(DISTINCT package_name) FROM vulnerabilities WHERE package_name IS NOT NULL;
\timing off

-- =============================================
-- 11. BENCHMARK: PROCEDIMIENTO ALMACENADO vs QUERY DIRECTA
-- =============================================
\echo ''
\echo '--- [11] BENCHMARK: Stored Procedure vs Query Directa ---'
\echo ''

\echo 'Escenario A: Filtro por severidad + paginacion (simula Vista Tables)'
\echo '  [SP] sp_get_vulnerabilities(severity=Critical, limit=20, offset=0):'
\timing on
SELECT * FROM sp_get_vulnerabilities(
    p_severity := 'Critical',
    p_limit := 20,
    p_offset := 0
);
\timing off

\echo '  [Query Directa] SELECT * con WHERE + LIMIT:'
\timing on
SELECT * FROM vulnerabilities
WHERE severity = 'Critical'
ORDER BY id ASC
LIMIT 20 OFFSET 0;
\timing off

\echo ''
\echo 'Escenario B: Filtro multi-parametro (simula Filtros de usuario)'
\echo '  [SP] sp_get_vulnerabilities(severity=High, status=Active, agent_group=default):'
\timing on
SELECT * FROM sp_get_vulnerabilities(
    p_severity := 'High',
    p_status := 'Active',
    p_agent_group := 'default',
    p_limit := 12,
    p_offset := 0
);
\timing off

\echo '  [Query Directa] SELECT con WHERE compuesto:'
\timing on
SELECT * FROM vulnerabilities
WHERE severity = 'High'
    AND status = 'Active'
    AND agent_group = 'default'
ORDER BY id ASC
LIMIT 12 OFFSET 0;
\timing off

\echo ''
\echo 'Escenario C: Conteo total con filtros (simula paginacion)'
\echo '  [SP] sp_count_vulnerabilities(severity=Critical):'
\timing on
SELECT sp_count_vulnerabilities(p_severity := 'Critical');
\timing off

\echo '  [Query Directa] COUNT(*) con WHERE:'
\timing on
SELECT count(*) FROM vulnerabilities WHERE severity = 'Critical';
\timing off

-- =============================================
-- 12. EXPLAIN ANALYZE - Plan de ejecucion del SP
-- =============================================
\echo ''
\echo '--- [12] EXPLAIN ANALYZE - Plan del Stored Procedure ---'
\echo 'Plan de ejecucion: sp_get_vulnerabilities con filtros combinados'
EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
SELECT * FROM sp_get_vulnerabilities(
    p_severity := 'High',
    p_agent_group := 'default',
    p_status := 'Active',
    p_min_cvss := 7.0,
    p_limit := 12,
    p_offset := 0
);

\echo ''
\echo 'Plan de ejecucion: sp_count_vulnerabilities con filtros combinados'
EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
SELECT sp_count_vulnerabilities(
    p_severity := 'High',
    p_agent_group := 'default',
    p_status := 'Active',
    p_min_cvss := 7.0
);

-- =============================================
-- 13. EXPLAIN ANALYZE - Query sin SP para comparar
-- =============================================
\echo ''
\echo '--- [13] EXPLAIN ANALYZE - Query directa para comparar ---'
EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
SELECT * FROM vulnerabilities
WHERE severity = 'High'
    AND agent_group = 'default'
    AND status = 'Active'
    AND cvss3_score >= 7.0
ORDER BY id ASC
LIMIT 12 OFFSET 0;

-- =============================================
-- 14. TIMESCALEDB - CHUNCKS Y COMPRESION
-- =============================================
\echo ''
\echo '--- [14] TIMESCALEDB - Analisis de Chunks ---'
SELECT
    chunk_name,
    is_compressed AS comprimido,
    primary_dimension AS dimension,
    range_start,
    range_end,
    pg_size_pretty(pg_total_relation_size(chunk_schema || '.' || chunk_name)) AS tamano_total
FROM timescaledb_information.chunks
WHERE hypertable_name = 'vulnerabilities'
ORDER BY range_start DESC
LIMIT 10;

-- =============================================
-- 15. POLITICA DE COMPRESION
-- =============================================
\echo ''
\echo '--- [15] TIMESCALEDB - Configuracion de Compresion ---'
SELECT
    hypertable_name AS tabla,
    attname AS columna_segmentada
FROM timescaledb_information.compression_settings
WHERE hypertable_name = 'vulnerabilities';

-- =============================================
-- 16. RESUMEN DE SALUD DEL SISTEMA
-- =============================================
\echo ''
\echo '--- [16] RESUMEN DE SALUD ---'
SELECT
    (SELECT count(*) FROM pg_stat_user_indexes
     WHERE schemaname = 'public' AND relname = 'vulnerabilities') AS total_indices,
    (SELECT count(*) FROM pg_stat_user_indexes
     WHERE schemaname = 'public' AND relname = 'vulnerabilities' AND idx_scan > 0) AS indices_en_uso,
    (SELECT count(*) FROM pg_stat_user_indexes
     WHERE schemaname = 'public' AND relname = 'vulnerabilities' AND idx_scan = 0) AS indices_sin_uso,
    (SELECT count(*) FROM pg_matviews WHERE schemaname = 'public') AS vistas_materializadas,
    (SELECT count(*) FROM information_schema.routines
     WHERE routine_schema = 'public' AND routine_type = 'FUNCTION') AS procedimientos_almacenados,
    pg_size_pretty(pg_database_size(current_database())) AS tamano_total_db,
    (SELECT count(*) FROM vulnerabilities) AS total_registros;

\echo ''
\echo '============================================================='
\echo '  FIN DEL BENCHMARK DASHBOARD'
\echo '============================================================='
\echo ''
