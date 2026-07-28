-- ================================================================
-- SCRIPT DE DATOS DE PRUEBA PARA LA LÍNEA DE TIEMPO
-- Replica las vulnerabilidades del 10 de julio en 11 meses
-- adicionales para visualizar 12 puntos en el timeline.
-- ================================================================
-- Meses objetivo (anteriores al sync actual 2026-07-10):
--   2025-08-10, 2025-09-10, 2025-10-10, 2025-11-10, 2025-12-10
--   2026-01-10, 2026-02-10, 2026-03-10, 2026-04-10, 2026-05-10, 2026-06-10
-- ================================================================

BEGIN;

-- ----------------------------------------------------------------
-- 1. Asegurar que las vulns originales (2026-07-10) tienen first_seen_sync
-- ----------------------------------------------------------------
UPDATE public.vulnerabilities
SET    first_seen_sync = DATE(last_sync)
WHERE  first_seen_sync IS NULL;

-- ----------------------------------------------------------------
-- 2. Función auxiliar para replicar un mes dado
--    Usamos un bloque DO anonimo para iterar los 11 meses
-- ----------------------------------------------------------------
DO $$
DECLARE
    month_offsets INT[] := ARRAY[-11, -10, -9, -8, -7, -6, -5, -4, -3, -2, -1];
    offset_months INT;
    sync_date     DATE;
    inserted_new  INT;
    inserted_res  INT;
    next_id       BIGINT;
BEGIN
    FOREACH offset_months IN ARRAY month_offsets LOOP
        -- Fecha de sync de ese mes (mismo día 10, N meses atrás del 2026-07-10)
        sync_date := ('2026-07-10'::DATE + (offset_months || ' months')::INTERVAL)::DATE;

        RAISE NOTICE 'Procesando mes: %', sync_date;

        -- Obtener el siguiente id disponible
        SELECT COALESCE(MAX(id), 0) + 1 INTO next_id FROM public.vulnerabilities;

        -- Insertar réplicas del mes de julio con fechas ajustadas
        INSERT INTO public.vulnerabilities (
            agent_group, agent_id, agent_name, cve, cvss3_score,
            description, detection_time, last_sync,
            package_name, package_version, resolved_at,
            severity, status, title, first_seen_sync
        )
        SELECT
            v.agent_group,
            v.agent_id,
            v.agent_name,
            -- El CVE se mantiene igual (representa misma vuln)
            v.cve,
            v.cvss3_score,
            v.description,
            -- detection_time ajustada al mes correspondiente
            v.detection_time + (offset_months || ' months')::INTERVAL,
            -- last_sync = fecha del sync de ese mes
            (sync_date || ' 03:00:00')::TIMESTAMP,
            v.package_name,
            v.package_version,
            -- ~20% resueltas en meses anteriores (usando módulo sobre el id para determinismo)
            CASE
                WHEN MOD(v.id, 5) = 0 THEN
                    (sync_date || ' 04:30:00')::TIMESTAMP
                ELSE NULL
            END,
            v.severity,
            CASE
                WHEN MOD(v.id, 5) = 0 THEN 'Resolved'
                ELSE 'Active'
            END,
            v.title,
            -- first_seen_sync = fecha del sync de ese mes (primera vez en ese mes)
            sync_date
        FROM public.vulnerabilities v
        WHERE v.first_seen_sync = '2026-07-10'::DATE;

        GET DIAGNOSTICS inserted_new = ROW_COUNT;
        RAISE NOTICE '  -> % filas insertadas para %', inserted_new, sync_date;

        -- Contar cuántas quedaron Resolved
        SELECT COUNT(*) INTO inserted_res
        FROM public.vulnerabilities
        WHERE first_seen_sync = sync_date AND status = 'Resolved';

        RAISE NOTICE '  -> % de ellas marcadas como Resolved', inserted_res;

    END LOOP;
END;
$$;

-- ----------------------------------------------------------------
-- 3. Limpiar vulnerability_timeline_events y regenerar desde cero
-- ----------------------------------------------------------------
TRUNCATE TABLE public.vulnerability_timeline_events;

-- Eventos NEW: una entrada por vuln en su sync_date de primera aparición
INSERT INTO public.vulnerability_timeline_events
    (sync_date, vulnerability_id, cve, severity, agent_id, event_type, agent_name, cvss3_score, package_name, status, detection_time)
SELECT
    first_seen_sync,
    id,
    cve,
    severity,
    agent_id,
    'NEW',
    agent_name,
    cvss3_score,
    package_name,
    status,
    detection_time
FROM public.vulnerabilities
WHERE first_seen_sync IS NOT NULL
ORDER BY first_seen_sync, id;

-- Eventos RESOLVED: vulns marcadas como Resolved (por fecha de resolved_at)
INSERT INTO public.vulnerability_timeline_events
    (sync_date, vulnerability_id, cve, severity, agent_id, event_type, agent_name, cvss3_score, package_name, status, detection_time)
SELECT
    DATE(resolved_at),
    id,
    cve,
    severity,
    agent_id,
    'RESOLVED',
    agent_name,
    cvss3_score,
    package_name,
    status,
    detection_time
FROM public.vulnerabilities
WHERE resolved_at IS NOT NULL
ORDER BY DATE(resolved_at), id;

-- ----------------------------------------------------------------
-- 4. Resumen final
-- ----------------------------------------------------------------
SELECT
    tle.sync_date,
    SUM(CASE WHEN tle.event_type = 'NEW'      THEN 1 ELSE 0 END) AS nuevas,
    SUM(CASE WHEN tle.event_type = 'RESOLVED' THEN 1 ELSE 0 END) AS resueltas
FROM public.vulnerability_timeline_events tle
GROUP BY tle.sync_date
ORDER BY tle.sync_date;

COMMIT;
