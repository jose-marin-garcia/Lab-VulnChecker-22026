#!/bin/bash
# =============================================================
# VULNCHECKER - Benchmark Completo con Docker
# Arranca la DB, importa datos y ejecuta el dashboard completo.
# Uso: ./scripts/run_benchmark.sh
# =============================================================

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

DB_CONTAINER="vuln-db"
DB_USER="${DB_USERNAME:-vulnuser}"
DB_PASS="${DB_PASSWORD:-vulnpass}"
DB_NAME="vulncheck"
DB_PORT="5433"

echo ""
echo -e "${CYAN}=============================================${NC}"
echo -e "${CYAN}  VULNCHECKER - BENCHMARK COMPLETO          ${NC}"
echo -e "${CYAN}=============================================${NC}"
echo ""

# =============================================
# PASO 1: Levantar solo la base de datos
# =============================================
echo -e "${YELLOW}[1/5] Levantando base de datos PostgreSQL + TimescaleDB...${NC}"

# Verificar si Docker esta corriendo
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}ERROR: Docker no esta corriendo. Inicia Docker Desktop.${NC}"
    exit 1
fi

# Detener contenedor previo si existe
docker compose down 2>/dev/null || true
docker compose rm -f 2>/dev/null || true

# Levantar solo db
docker compose up -d db

echo -e "${YELLOW}Esperando a que PostgreSQL este listo...${NC}"
for i in $(seq 1 30); do
    if docker compose exec -T db pg_isready -U "$DB_USER" -d "$DB_NAME" > /dev/null 2>&1; then
        echo -e "${GREEN}  PostgreSQL listo.${NC}"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo -e "${RED}  ERROR: PostgreSQL no respondio en 30 segundos.${NC}"
        exit 1
    fi
    sleep 1
done

echo ""

# =============================================
# PASO 2: Verificar esquema (init.sql ya se ejecuto via docker-entrypoint)
# =============================================
echo -e "${YELLOW}[2/5] Verificando esquema de base de datos...${NC}"

# Verificar que las tablas existen
TABLES=$(docker compose exec -T db psql -U "$DB_USER" -d "$DB_NAME" -t -c "
    SELECT count(*) FROM information_schema.tables
    WHERE table_schema = 'public'
    AND table_name IN ('vulnerabilities', 'vulnerability_snapshots', 'users')
" 2>/dev/null | tr -d ' ')

if [ "$TABLES" -lt 3 ]; then
    echo -e "${YELLOW}  Esquema no encontrado. Creando desde init.sql...${NC}"
    docker compose exec -T db psql -U "$DB_USER" -d "$DB_NAME" -f /docker-entrypoint-initdb.d/init.sql > /dev/null 2>&1
    echo -e "${GREEN}  Esquema creado.${NC}"
else
    echo -e "${GREEN}  Esquema verificado ($TABLES tablas principales).${NC}"
fi

# Verificar stored procedures
SP_COUNT=$(docker compose exec -T db psql -U "$DB_USER" -d "$DB_NAME" -t -c "
    SELECT count(*) FROM information_schema.routines
    WHERE routine_schema = 'public'
    AND routine_name IN ('sp_get_vulnerabilities', 'sp_count_vulnerabilities')
" 2>/dev/null | tr -d ' ')

echo -e "${GREEN}  Stored procedures: $SP_COUNT/2.${NC}"

# Verificar vistas materializadas
MV_COUNT=$(docker compose exec -T db psql -U "$DB_USER" -d "$DB_NAME" -t -c "
    SELECT count(*) FROM pg_matviews WHERE schemaname = 'public'
" 2>/dev/null | tr -d ' ')
echo -e "${GREEN}  Vistas materializadas: $MV_COUNT/4.${NC}"

echo ""

# =============================================
# PASO 3: Importar datos del dump
# =============================================
echo -e "${YELLOW}[3/5] Importando datos del dump (pobladovulns.sql)...${NC}"

ROW_COUNT=$(docker compose exec -T db psql -U "$DB_USER" -d "$DB_NAME" -t -c "
    SELECT count(*) FROM vulnerabilities
" 2>/dev/null | tr -d ' ')

if [ "$ROW_COUNT" -gt 0 ]; then
    echo -e "${GREEN}  Tabla ya tiene $ROW_COUNT registros. Saltando importacion.${NC}"
else
    # Crear tabla temporal con el esquema del dump y cargar los datos
    docker compose exec -T db psql -U "$DB_USER" -d "$DB_NAME" <<-'EOSQL'
        -- Crear tabla temporal con esquema del dump
        CREATE TEMPORARY TABLE IF NOT EXISTS vuln_dump (
            id SERIAL PRIMARY KEY,
            wazuh_doc_id TEXT,
            agent_id TEXT, agent_name TEXT, agent_type TEXT, agent_version TEXT,
            os_full TEXT, os_kernel TEXT, os_name TEXT, os_platform TEXT, os_version TEXT,
            package_name TEXT, package_version TEXT, package_architecture TEXT,
            package_type TEXT, package_size BIGINT, package_installed TIMESTAMPTZ,
            cve_id TEXT, severity TEXT, category TEXT, classification TEXT, description TEXT,
            score_base NUMERIC(4,1), score_version TEXT, enumeration TEXT,
            published_at TIMESTAMPTZ, detected_at TIMESTAMPTZ,
            reference TEXT, scanner_vendor TEXT, scanner_source TEXT,
            under_evaluation BOOLEAN, wazuh_cluster TEXT, wazuh_schema_version TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
EOSQL

    # Copiar el SQL del dump al contenedor y ejecutar
    docker cp pobladovulns.sql "$DB_CONTAINER":/tmp/pobladovulns.sql
    docker compose exec -T db bash -c "psql -U $DB_USER -d $DB_NAME -f /tmp/pobladovulns.sql" > /dev/null 2>&1

    # Mapear datos de la tabla temporal a la tabla principal de produccion
    docker compose exec -T db psql -U "$DB_USER" -d "$DB_NAME" <<-'EOSQL'
        INSERT INTO vulnerabilities (
            agent_id, agent_name, agent_group, cve, severity, status,
            cvss3_score, description, package_name, package_version,
            detection_time, last_sync, title
        )
        SELECT
            v.agent_id,
            COALESCE(v.agent_name, v.wazuh_cluster),
            COALESCE(v.wazuh_cluster, 'default'),
            v.cve_id,
            v.severity,
            'Active',
            v.score_base,
            LEFT(COALESCE(v.description, ''), 2000),
            v.package_name,
            v.package_version,
            COALESCE(v.detected_at, NOW()),
            NOW(),
            COALESCE(v.classification, v.category, 'N/A')
        FROM vuln_dump v
        WHERE v.cve_id IS NOT NULL;

        -- Refrescar vistas materializadas
        REFRESH MATERIALIZED VIEW CONCURRENTLY mv_vulnerabilities_severities;
        REFRESH MATERIALIZED VIEW CONCURRENTLY mv_vulnerabilities_status;
        REFRESH MATERIALIZED VIEW CONCURRENTLY mv_vulnerabilities_groups;
        REFRESH MATERIALIZED VIEW CONCURRENTLY mv_vulnerabilities_packages;
EOSQL

    ROW_COUNT=$(docker compose exec -T db psql -U "$DB_USER" -d "$DB_NAME" -t -c "
        SELECT count(*) FROM vulnerabilities
    " 2>/dev/null | tr -d ' ')
    echo -e "${GREEN}  Importados $ROW_COUNT registros en tabla vulnerabilities.${NC}"
fi

echo ""

# =============================================
# PASO 4: Ejecutar el Dashboard de Benchmark
# =============================================
echo -e "${YELLOW}[4/5] Ejecutando Benchmark Dashboard...${NC}"
echo ""

docker compose exec -T db psql -U "$DB_USER" -d "$DB_NAME" -f /dev/stdin < scripts/benchmark_dashboard.sql

echo ""

# =============================================
# PASO 5: Resumen final
# =============================================
echo -e "${YELLOW}[5/5] Resumen...${NC}"
echo ""

# Estadisticas rapidas
docker compose exec -T db psql -U "$DB_USER" -d "$DB_NAME" <<-'EOSQL'
    \echo ''
    \echo '============================================================='
    \echo '  RESUMEN FINAL'
    \echo '============================================================='

    SELECT
        (SELECT count(*) FROM vulnerabilities) AS total_vulnerabilities,
        (SELECT count(DISTINCT severity) FROM vulnerabilities) AS severidades,
        (SELECT count(DISTINCT agent_id) FROM vulnerabilities) AS agentes,
        (SELECT count(DISTINCT cve) FROM vulnerabilities) AS cves_unicos,
        (SELECT count(DISTINCT package_name) FROM vulnerabilities) AS paquetes,
        pg_size_pretty(pg_database_size(current_database())) AS tamano_db;

    \echo ''
    \echo '  Backend:  http://localhost:8080'
    \echo '  Frontend: http://localhost:5173'
    \echo '  DB:       localhost:5433'
    \echo ''
    \echo '============================================================='
EOSQL

echo ""
echo -e "${GREEN}Benchmark completado.${NC}"
echo -e "${YELLOW}Para detener la DB: docker compose down${NC}"
echo ""
