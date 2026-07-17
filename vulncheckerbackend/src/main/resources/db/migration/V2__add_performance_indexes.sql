-- V2: Performance indexes for vulnerabilities at scale (25M+ rows, 300 agents)
-- These indexes are designed for the specific query patterns used by the application.

-- 1. Upsert lookup: used by WazuhService.processAndSaveBatch() for duplicate detection
--    Query: findByCveAndAgentIdAndPackageName(cve, agentId, packageName)
--    NOTE: Not UNIQUE because TimescaleDB hypertables require the partition column
--    in any unique index. Uniqueness is enforced at the application level via upsert.
CREATE INDEX IF NOT EXISTS idx_vuln_sync_lookup
    ON vulnerabilities (cve, agent_id, package_name);

-- 2. Dashboard/charts: severity distribution and agent filtering
--    Used by VulnerabilityChartsRepository: countByCanonicalSeverity, countByAgent, countTotal
CREATE INDEX IF NOT EXISTS idx_vuln_severity_agent
    ON vulnerabilities (severity, agent_id);

-- 3. Mark and Sweep: bulk update old vulnerabilities to Resolved status
--    Used by VulnerabilityRepository.markAsResolvedForAgentsBefore()
--    Filters on last_sync < :syncTime AND status = 'Active'
CREATE INDEX IF NOT EXISTS idx_vuln_last_sync_status
    ON vulnerabilities (last_sync, status);

-- 4. Date range filters: detection time range queries from dashboard
--    Used by VulnerabilityService.findAllWithFilters() with startDate/endDate
CREATE INDEX IF NOT EXISTS idx_vuln_detection_time
    ON vulnerabilities (detection_time);

-- 5. High-priority filter: partial index for critical/high severity only
--    Checkbox "Solo alta prioridad" in dashboard
--    Partial index is smaller and faster than a full index
CREATE INDEX IF NOT EXISTS idx_vuln_high_priority
    ON vulnerabilities (severity, agent_id)
    WHERE LOWER(TRIM(COALESCE(severity, ''))) IN ('critical', 'high', 'alta', 'crítica', 'critica');

-- 6. Snapshot query optimization: latest snapshot per agent
--    Used by VulnerabilitySnapshotRepository.findLatestSnapshotsPerAgent()
CREATE INDEX IF NOT EXISTS idx_vsnap_agent_date
    ON vulnerability_snapshots (agent_id, snapshot_date DESC);

-- 7. Free-text search: trigram extension for LIKE '%text%' queries
--    Used by VulnerabilityChartsRepository.buildFilter() and VulnerabilityService search
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS idx_vuln_cve_trgm
    ON vulnerabilities USING gin (cve gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_vuln_package_name_trgm
    ON vulnerabilities USING gin (package_name gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_vuln_agent_name_trgm
    ON vulnerabilities USING gin (agent_name gin_trgm_ops);
