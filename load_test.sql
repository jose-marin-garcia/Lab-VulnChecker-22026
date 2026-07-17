-- =============================================================================
-- LOAD TEST SCRIPT: 2,000,000 realistic vulnerabilities
-- For VulnChecker database performance testing
--
-- Usage:
--   1. Start DB: docker compose up -d db
--   2. Connect:  psql -h localhost -p 5433 -U admin -d vulncheck
--   3. Run:      \i load_test.sql
--   4. The script creates data, runs benchmark queries, and reports timing.
-- =============================================================================

\timing on

-- Step 1: Create temporary table with 2M realistic vulnerabilities
-- This simulates what Wazuh would produce for 300 agents
DO $$
DECLARE
    start_time TIMESTAMP;
    end_time TIMESTAMP;
BEGIN
    start_time := clock_timestamp();

    RAISE NOTICE 'Creating temporary table with 2,000,000 vulnerabilities...';

    DROP TABLE IF EXISTS temp_vuln_load;

    CREATE TEMPORARY TABLE temp_vuln_load AS
    SELECT
        -- Agent: 300 agents (ID 1001-1300)
        'agent-' || (1000 + (g % 300) + 1)::text AS agent_name,
        ((g % 300) + 1001)::text AS agent_id,
        'group-' || (((g % 300) % 10) + 1)::text AS agent_group,

        -- CVE: pseudo-realistic CVE IDs (CVE-2024-10001 to CVE-2024-99999)
        'CVE-2024-' || LPAD(((g % 99999) + 1)::text, 5, '0') AS cve,

        -- Title and description
        'Vulnerability in package affecting system ' || ((g % 300) + 1)::text AS title,
        'A security vulnerability was found in the software package. ' ||
        'This issue affects component at revision ' || (g % 1000)::text || '.' AS description,

        -- Severity distribution: 5% critical, 15% high, 40% medium, 40% low
        CASE
            WHEN (g % 100) < 5  THEN 'Critical'
            WHEN (g % 100) < 20 THEN 'High'
            WHEN (g % 100) < 60 THEN 'Medium'
            ELSE 'Low'
        END AS severity,

        -- CVSS3 score aligned with severity
        CASE
            WHEN (g % 100) < 5  THEN 9.0 + (random() * 1.0)
            WHEN (g % 100) < 20 THEN 7.0 + (random() * 1.9)
            WHEN (g % 100) < 60 THEN 4.0 + (random() * 2.9)
            ELSE 0.1 + (random() * 3.9)
        END::numeric(3,1) AS cvss3_score,

        -- Package: common software packages
        (ARRAY['openssl', 'linux-kernel', 'curl', 'sudo', 'systemd',
                'openssh', 'glibc', 'bash', 'nginx', 'postgresql',
                'python3', 'nodejs', 'java-17-openjdk', 'vim', 'git',
                'docker.io', 'kubernetes', 'redis', 'mysql', 'mongodb'])[1 + (g % 20)] AS package_name,

        -- Package version
        (floor(random() * 10) + 1)::text || '.' ||
        (floor(random() * 20))::text || '.' ||
        (floor(random() * 50))::text AS package_version,

        -- Detection time: distributed over last 12 months
        NOW() - (floor(random() * 365) || ' days')::interval
            - (floor(random() * 24) || ' hours')::interval AS detection_time,

        -- Status: 85% Active, 15% Resolved
        CASE WHEN (g % 100) < 85 THEN 'Active' ELSE 'Resolved' END AS status,

        -- Timestamps
        NOW() - (floor(random() * 30) || ' days')::interval AS last_sync,
        CASE WHEN (g % 100) >= 85
            THEN NOW() - (floor(random() * 60) || ' days')::interval
        END AS resolved_at
    FROM generate_series(1, 2000000) AS g;

    end_time := clock_timestamp();
    RAISE NOTICE 'Temp table created in % ms', extract(milliseconds FROM end_time - start_time);
END $$;

-- Step 2: Verify row count
SELECT 'Total rows created: ' || COUNT(*)::text FROM temp_vuln_load;

-- Step 3: Show severity distribution
SELECT severity, COUNT(*) AS count,
       ROUND(COUNT(*) * 100.0 / 2000000, 1) AS pct
FROM temp_vuln_load
GROUP BY severity
ORDER BY CASE severity
    WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
    WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 END;

-- Step 4: Show agent distribution (first 10)
SELECT agent_id, agent_name, COUNT(*) AS vuln_count
FROM temp_vuln_load
GROUP BY agent_id, agent_name
ORDER BY vuln_count DESC
LIMIT 10;

-- Step 5: Insert into actual vulnerabilities table (if it exists)
-- This measures real INSERT performance
DO $$
DECLARE
    start_time TIMESTAMP;
    end_time TIMESTAMP;
    batch_size INT := 5000;
    total_rows INT;
    rows_inserted INT := 0;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'vulnerabilities') THEN
        RAISE NOTICE 'Table vulnerabilities does not exist yet. Skipping insert.';
        RETURN;
    END IF;

    SELECT COUNT(*) INTO total_rows FROM temp_vuln_load;
    start_time := clock_timestamp();

    RAISE NOTICE 'Inserting % rows into vulnerabilities table in batches of %...', total_rows, batch_size;

    -- Insert in batches
    INSERT INTO vulnerabilities (
        agent_name, agent_id, agent_group, cve, title, description,
        severity, cvss3_score, package_name, package_version,
        detection_time, status, last_sync, resolved_at
    )
    SELECT
        agent_name, agent_id, agent_group, cve, title, description,
        severity, cvss3_score, package_name, package_version,
        detection_time, status, last_sync, resolved_at
    FROM temp_vuln_load;

    GET DIAGNOSTICS rows_inserted = ROW_COUNT;
    end_time := clock_timestamp();

    RAISE NOTICE 'Inserted % rows in % ms (%.1f rows/sec)',
        rows_inserted,
        extract(milliseconds FROM end_time - start_time),
        rows_inserted / greatest(extract(epoch FROM end_time - start_time), 0.001);
END $$;

-- Step 6: Verify final count
SELECT 'Rows in vulnerabilities table: ' || COUNT(*)::text FROM vulnerabilities;

-- =============================================================================
-- BENCHMARK QUERIES: Run these before and after adding indexes to compare
-- =============================================================================

-- B1: Upsert lookup (most critical - runs 25M times during sync)
EXPLAIN ANALYZE
SELECT id FROM vulnerabilities
WHERE cve = 'CVE-2024-50000' AND agent_id = '1050' AND package_name = 'openssl';

-- B2: Severity distribution (dashboard chart)
EXPLAIN ANALYZE
SELECT LOWER(TRIM(COALESCE(severity, ''))) AS name, COUNT(*) AS value
FROM vulnerabilities v
WHERE 1=1
GROUP BY name
ORDER BY CASE name
    WHEN 'critical' THEN 1 WHEN 'high' THEN 2
    WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END;

-- B3: Agent count (dashboard chart)
EXPLAIN ANALYZE
SELECT COALESCE(NULLIF(TRIM(agent_name), ''), NULLIF(TRIM(agent_id), ''), 'Sin dato') AS name,
       COUNT(*) AS value
FROM vulnerabilities v
WHERE 1=1
GROUP BY name
ORDER BY value DESC, name ASC
LIMIT 10;

-- B4: High-priority filter
EXPLAIN ANALYZE
SELECT COUNT(*) FROM vulnerabilities
WHERE LOWER(TRIM(COALESCE(severity, ''))) IN ('critical', 'high', 'alta', 'crítica', 'critica');

-- B5: Date range filter
EXPLAIN ANALYZE
SELECT COUNT(*) FROM vulnerabilities
WHERE detection_time >= '2024-01-01' AND detection_time <= '2024-06-30';

-- B6: Mark and Sweep (bulk update simulation)
EXPLAIN ANALYZE
SELECT id FROM vulnerabilities
WHERE agent_id IN ('1001', '1002', '1003', '1004', '1005')
  AND last_sync < '2024-06-01'
  AND status = 'Active';

-- B7: Free-text search on CVE
EXPLAIN ANALYZE
SELECT id, cve, title FROM vulnerabilities
WHERE LOWER(cve) LIKE '%50000%'
LIMIT 50;

-- B8: CVE count for chart (top N)
EXPLAIN ANALYZE
SELECT COALESCE(NULLIF(UPPER(TRIM(cve)), ''), 'Sin dato') AS name, COUNT(*) AS value
FROM vulnerabilities v
WHERE 1=1
GROUP BY name
ORDER BY value DESC, name ASC
LIMIT 10;

-- Cleanup: remove temp table
DROP TABLE IF EXISTS temp_vuln_load;

-- =============================================================================
-- SUMMARY
-- =============================================================================
SELECT 'Load test complete. Check EXPLAIN ANALYZE results above for timing.';
