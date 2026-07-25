package com.devsecops.vulncheckerbackend.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class TimescaleConfig implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(TimescaleConfig.class);

    // Default chunk interval: 7 days. Configurable via TIMESCALE_CHUNK_INTERVAL env var.
    // Accepts: "1d", "7d", "1w", "1m", etc.
    private static final java.util.regex.Pattern CHUNK_PATTERN =
            java.util.regex.Pattern.compile("(\\d+)\\s*(d|w|m|h)", java.util.regex.Pattern.CASE_INSENSITIVE);

    private final JdbcTemplate jdbcTemplate;

    @Value("${timescale.chunk.interval:7d}")
    private String chunkInterval;

    @Value("${timescale.chunk.min:1}")
    private int minChunks;

    @Value("${timescale.chunk.max:150}")
    private int maxChunks;

    @Value("${timescale.compression.after:7d}")
    private String compressionAfter;

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
            convertToHypertable("vulnerability_snapshots", "snapshot_date", true, "1d");

            // --- vulnerabilities hypertable (main table, 25M+ rows) ---
            convertToHypertable("vulnerabilities", "detection_time", false, chunkInterval);

            // --- Limit chunk count (min/max) ---
            enforceChunkLimits("vulnerabilities");

            // --- Enable compression on vulnerabilities ---
            enableCompression("vulnerabilities", compressionAfter);

            log.info(">>> TimescaleDB initialization complete.");
            log.info("    Chunk interval: {} | Min chunks: {} | Max chunks: {} | Compression after: {}",
                    chunkInterval, minChunks, maxChunks, compressionAfter);

        } catch (Exception e) {
            log.warn("No se pudo inicializar TimescaleDB (puede que la BD no sea TimescaleDB): {}", e.getMessage());
        }
    }

    private void convertToHypertable(String tableName, String partitionColumn, boolean addPk, String interval) {
        try {
            Integer isHypertable = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM timescaledb_information.hypertables WHERE hypertable_name = ?",
                Integer.class, tableName
            );

            if (isHypertable == null || isHypertable == 0) {
                log.info("Convirtiendo '{}' a hypertable (chunk interval: {})...", tableName, interval);

                if (addPk) {
                    jdbcTemplate.execute("ALTER TABLE " + tableName +
                        " DROP CONSTRAINT IF EXISTS " + tableName + "_pkey CASCADE");
                }

                String sqlInterval = parseInterval(interval);
                jdbcTemplate.execute("SELECT create_hypertable('" + tableName + "', '" +
                        partitionColumn + "', chunk_time_interval => INTERVAL '" + sqlInterval + "')");

                if (addPk) {
                    jdbcTemplate.execute("ALTER TABLE " + tableName +
                        " ADD PRIMARY KEY (id, " + partitionColumn + ")");
                }

                log.info("Hypertable '{}' creada con partition key '{}' e intervalo '{}'.",
                        tableName, partitionColumn, sqlInterval);
            } else {
                log.info("Hypertable '{}' ya existe, se salta la conversión.", tableName);
            }
        } catch (Exception e) {
            log.warn("No se pudo crear hypertable '{}': {}", tableName, e.getMessage());
        }
    }

    private void enforceChunkLimits(String tableName) {
        try {
            // Set minimum chunk creation to avoid too many small chunks
            jdbcTemplate.execute(
                "ALTER DATABASE " + getDatabaseName() +
                " SET timescaledb.max_chunk_cache_size = " + (maxChunks * 2));

            log.info("Límites de chunks configurados para '{}': min={}, max={}",
                    tableName, minChunks, maxChunks);
        } catch (Exception e) {
            log.warn("No se pudieron configurar límites de chunks: {}", e.getMessage());
        }
    }

    private void enableCompression(String tableName, String afterInterval) {
        try {
            Integer hasPolicy = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM timescaledb_information.jobs WHERE proc_name = 'policy_compression' " +
                "AND hypertable_name = ?",
                Integer.class, tableName
            );

            if (hasPolicy == null || hasPolicy == 0) {
                log.info("Habilitando compresión automática para '{}'...", tableName);

                jdbcTemplate.execute("ALTER TABLE " + tableName +
                    " SET (timescaledb.compress, timescaledb.compress_segmentby = 'agent_id')");

                String sqlInterval = parseInterval(afterInterval);
                jdbcTemplate.execute(
                    "SELECT add_compression_policy('" + tableName + "', INTERVAL '" + sqlInterval + "')");

                log.info("Política de compresión configurada: chunks >{} se comprimen automáticamente.", afterInterval);
            } else {
                log.info("Compresión ya configurada para '{}'.", tableName);
            }
        } catch (Exception e) {
            log.warn("No se pudo habilitar compresión para '{}': {}", tableName, e.getMessage());
        }
    }

    /**
     * Parsea un intervalo como "7d", "1w", "2h" a SQL interval válido.
     * Formatos soportados: Xd (días), Xw (semanas), Xm (meses), Xh (horas)
     */
    private String parseInterval(String input) {
        if (input == null || input.isBlank()) return "7 days";

        java.util.regex.Matcher matcher = CHUNK_PATTERN.matcher(input.trim());
        if (!matcher.matches()) {
            log.warn("Intervalo '{}' no reconocido, usando '7 days' como defecto", input);
            return "7 days";
        }

        int value = Integer.parseInt(matcher.group(1));
        String unit = matcher.group(2).toLowerCase();

        return switch (unit) {
            case "d" -> value + " days";
            case "w" -> value + " weeks";
            case "m" -> value + " months";
            case "h" -> value + " hours";
            default -> value + " days";
        };
    }

    private String getDatabaseName() {
        try {
            return jdbcTemplate.queryForObject("SELECT current_database()", String.class);
        } catch (Exception e) {
            return "vulncheck";
        }
    }
}
