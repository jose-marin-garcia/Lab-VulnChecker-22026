# 🔒 Cifrado y Autenticación Mutua (mTLS) entre Backend y Base de Datos

Este documento explica la arquitectura de seguridad, la generación de certificados y los pasos para habilitar **Mutual TLS (mTLS)** entre el backend (**Spring Boot**) y la base de datos (**TimescaleDB / PostgreSQL 16**).

---

## 🎯 ¿Por qué mTLS?

En una arquitectura Zero-Trust estándar de DevSecOps:
1. **Cifrado en tránsito (TLS):** Todo el tráfico TCP entre el backend y PostgreSQL viaja cifrado (protege consultas SQL, hashes y datos confidenciales).
2. **Autenticación del Servidor:** El backend valida la identidad de la base de datos contra una Autoridad Certificadora (CA) propia (`sslmode=verify-full`), mitigando ataques Man-in-the-Middle (MitM).
3. **Autenticación del Cliente (mTLS):** PostgreSQL exige y valida criptográficamente el certificado del backend (`clientcert=verify-full` con método `cert`), asegurando que solo aplicaciones con certificados autorizados por la CA puedan interactuar con la BD.

---

## 🏗️ Arquitectura de Certificados (PKI Local)

La infraestructura de certificados se aloja en el directorio local `./certs`:

```
certs/
├── ca.crt          # Certificado público de la Autoridad Certificadora (CA Raíz)
├── ca.key          # Clave privada de la CA (restringida, 0600)
├── server.crt      # Certificado público del Servidor (PostgreSQL) con SAN (db, localhost)
├── server.key      # Clave privada del Servidor (0600, propiedad postgres)
├── client.crt      # Certificado público del Cliente (Backend) emitido para el usuario admin
├── client.key      # Clave privada del Cliente
├── client.pk8      # Clave privada del Cliente en formato PKCS#8 DER (requerido por PostgreSQL JDBC)
└── pg_hba.conf     # Reglas de autenticación de PostgreSQL forzando mTLS (clientcert=verify-full)
```

> [!NOTE]
> La carpeta `certs/*` está ignorada en `.gitignore` por seguridad, manteniendo únicamente el archivo de configuración `certs/pg_hba.conf` en el control de versiones.

---

## 🚀 Paso 1: Generación Automatizada de Certificados

El proyecto incluye el script `generate-certs.sh` en la raíz, el cual se encarga de crear la CA y generar los certificados firmados:

```bash
# Dar permisos de ejecución si es necesario
chmod +x generate-certs.sh

# Ejecutar el generador (usa el usuario de DB configurado en .env)
./generate-certs.sh
```

### ¿Qué realiza el script?
1. Crea la **CA Raíz** con validez extendida.
2. Genera el par clave/certificado para **PostgreSQL** (`server.crt` / `server.key`) con nombres alternativos de sujeto (SAN: `db`, `localhost`, `127.0.0.1`).
3. Genera el par clave/certificado para el **Backend** (`client.crt` / `client.key`) con `CN=${DB_USERNAME}` (por defecto `admin` o `vulnuser`).
4. Convierte la clave de cliente a formato **PKCS#8** (`client.pk8`) sin cifrado de clave para compatibilidad nativa con el driver PostgreSQL JDBC.
5. Asigna los permisos mínimos necesarios en Linux (`0600` para claves privadas y `0644` para certificados públicos).

---

## ⚙️ Paso 2: Configuración en `docker-compose.yml`

### 1. Servicio de Base de Datos (`vuln-db`)
PostgreSQL monta los certificados en `/mnt/certs` y los prepara antes de arrancar:

```yaml
  db:
    image: timescale/timescaledb:latest-pg16
    container_name: vuln-db
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql:z
      - ./certs:/mnt/certs:ro,z # Certificados SSL para conexión backend-db
    entrypoint:
      - "/bin/sh"
      - "-c"
      - |
        mkdir -p /var/lib/postgresql/certs
        cp /mnt/certs/* /var/lib/postgresql/certs/
        chmod 600 /var/lib/postgresql/certs/server.key
        chmod 644 /var/lib/postgresql/certs/server.crt /var/lib/postgresql/certs/ca.crt /var/lib/postgresql/certs/pg_hba.conf
        chown -R postgres:postgres /var/lib/postgresql/certs
        exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/var/lib/postgresql/certs/server.crt -c ssl_key_file=/var/lib/postgresql/certs/server.key -c ssl_ca_file=/var/lib/postgresql/certs/ca.crt -c hba_file=/var/lib/postgresql/certs/pg_hba.conf
```

### 2. Servicio de Backend (`vuln-backend`)
El backend monta los certificados en `/app/certs` y configura los parámetros JDBC:

```yaml
  backend:
    volumes:
      - ./vulncheckerbackend/src:/app/src:z
      - ./vulncheckerbackend/pom.xml:/app/pom.xml:z
      - ./vulncheckerbackend/.mvn:/app/.mvn:z
      - ./certs:/app/certs:ro,z # Certificados SSL para conexión backend-db
      - m2_cache:/root/.m2
    environment:
      - DB_USERNAME=${DB_USERNAME:-vulnuser}
      - DB_PASSWORD=${DB_PASSWORD:-vulnpass}
      - DB_O_LOCALHOST=db
      - SPRING_DATASOURCE_URL=jdbc:postgresql://db:5432/vulncheck?ssl=true&sslmode=verify-full&sslrootcert=/app/certs/ca.crt&sslcert=/app/certs/client.crt&sslkey=/app/certs/client.pk8
      - SPRING_FLYWAY_URL=jdbc:postgresql://db:5432/vulncheck?ssl=true&sslmode=verify-full&sslrootcert=/app/certs/ca.crt&sslcert=/app/certs/client.crt&sslkey=/app/certs/client.pk8
```

---

## 🛡️ Paso 3: Configuración de `pg_hba.conf`

El archivo `certs/pg_hba.conf` define que cualquier conexión TCP debe usar SSL y autenticarse mediante el certificado de cliente:

```text
# Conexiones socket locales (healthcheck del contenedor)
local   all             all                                     trust

# Conexiones TCP con mTLS obligatorio
hostssl all             all             127.0.0.1/32            cert clientcert=verify-full
hostssl all             all             all                     cert clientcert=verify-full
```

---

## 🔍 Paso 4: Verificación y Diagnóstico

### 1. Iniciar los servicios
```bash
docker compose up -d db backend
```

### 2. Verificar logs de PostgreSQL
```bash
docker compose logs db
```
Debe indicar que el sistema está listo y escuchando conexiones con SSL habilitado:
```
LOG:  database system is ready to accept connections
```

### 3. Verificar logs de Spring Boot
```bash
docker compose logs -f backend
```
Debe observarse la inicialización de Flyway e Hibernate completándose sin advertencias de handshake TLS:
```
INFO ... [main] c.d.v.VulncheckerbackendApplication : Started VulncheckerbackendApplication in ...
```

### 4. Consultar el Healthcheck del Backend
```bash
curl -s http://localhost:8080/actuator/health
# Salida esperada:
# {"groups":["liveness","readiness"],"status":"UP"}
```
