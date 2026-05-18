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

            Integer yaEsHypertable = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM timescaledb_information.hypertables WHERE hypertable_name = 'vulnerability_snapshots'",
                Integer.class
            );

            if (yaEsHypertable == null || yaEsHypertable == 0) {
                log.info("Convirtiendo 'vulnerability_snapshots' a hypertable...");

                jdbcTemplate.execute("""
                    ALTER TABLE vulnerability_snapshots
                    DROP CONSTRAINT IF EXISTS vulnerability_snapshots_pkey CASCADE
                """);

                jdbcTemplate.execute("""
                    SELECT create_hypertable('vulnerability_snapshots', 'snapshot_date')
                """);

                jdbcTemplate.execute("""
                    ALTER TABLE vulnerability_snapshots
                    ADD PRIMARY KEY (id, snapshot_date)
                """);

                log.info("Hypertable 'vulnerability_snapshots' creada con composite PK (id, snapshot_date).");
            } else {
                log.info("Hypertable 'vulnerability_snapshots' ya existe, se salta la conversión.");
            }

        } catch (Exception e) {
            log.warn("No se pudo inicializar TimescaleDB (puede que la BD no sea TimescaleDB): {}", e.getMessage());
        }
    }
}
