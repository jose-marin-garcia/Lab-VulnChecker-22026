package com.devsecops.vulncheckerbackend.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class TimescaleConfig implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(TimescaleConfig.class);

    private final JdbcTemplate jdbcTemplate;

    public TimescaleConfig(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public void run(ApplicationArguments args) {
        try {
            log.info(">>> Inicializando TimescaleDB...");

            jdbcTemplate.execute("CREATE EXTENSION IF NOT EXISTS timescaledb");
            log.info("Extensión timescaledb creada/verificada.");

            // --- vulnerability_snapshots hypertable ---
            convertToHypertable("vulnerability_snapshots", "snapshot_date", true);

            // --- vulnerabilities hypertable (main table, 25M+ rows) ---
            convertToHypertable("vulnerabilities", "detection_time", false);

            // --- Enable compression on vulnerabilities (chunks older than 7 days) ---
            enableCompression("vulnerabilities");

            log.info(">>> TimescaleDB initialization complete.");

        } catch (Exception e) {
            log.warn("No se pudo inicializar TimescaleDB (puede que la BD no sea TimescaleDB): {}", e.getMessage());
        }
    }

    private void convertToHypertable(String tableName, String partitionColumn, boolean addPk) {
        try {
            Integer isHypertable = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM timescaledb_information.hypertables WHERE hypertable_name = ?",
                Integer.class, tableName
            );

            if (isHypertable == null || isHypertable == 0) {
                log.info("Convirtiendo '{}' a hypertable...", tableName);

                if (addPk) {
                    jdbcTemplate.execute("ALTER TABLE " + tableName +
                        " DROP CONSTRAINT IF EXISTS " + tableName + "_pkey CASCADE");
                }

                jdbcTemplate.execute("SELECT create_hypertable('" + tableName + "', '" + partitionColumn + "')");

                if (addPk) {
                    jdbcTemplate.execute("ALTER TABLE " + tableName +
                        " ADD PRIMARY KEY (id, " + partitionColumn + ")");
                }

                log.info("Hypertable '{}' creada con partition key '{}'.", tableName, partitionColumn);
            } else {
                log.info("Hypertable '{}' ya existe, se salta la conversión.", tableName);
            }
        } catch (Exception e) {
            log.warn("No se pudo crear hypertable '{}': {}", tableName, e.getMessage());
        }
    }

    private void enableCompression(String tableName) {
        try {
            // Check if compression policy already exists
            Integer hasPolicy = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM timescaledb_information.jobs WHERE proc_name = 'policy_compression' " +
                "AND hypertable_name = ?",
                Integer.class, tableName
            );

            if (hasPolicy == null || hasPolicy == 0) {
                log.info("Habilitando compresión automática para '{}'...", tableName);

                jdbcTemplate.execute("ALTER TABLE " + tableName +
                    " SET (timescaledb.compress, timescaledb.compress_segmentby = 'agent_id')");

                // Compress chunks older than 7 days
                jdbcTemplate.execute(
                    "SELECT add_compression_policy('" + tableName + "', INTERVAL '7 days')");

                log.info("Política de compresión configurada: chunks >7 días se comprimen automáticamente.");
            } else {
                log.info("Compresión ya configurada para '{}'.", tableName);
            }
        } catch (Exception e) {
            log.warn("No se pudo habilitar compresión para '{}': {}", tableName, e.getMessage());
        }
    }
}
