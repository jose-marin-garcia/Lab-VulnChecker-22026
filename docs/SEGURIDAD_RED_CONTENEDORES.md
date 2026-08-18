# Seguridad de las conexiones y del entorno

## Medidas aplicadas en el proyecto

### Redes segmentadas

| Red | Servicios | Uso |
|-----|-----------|-----|
| **app_internal** (red interna, sin internet) | `db`, `backend` | Solo el backend puede hablar con la base de datos; la BD no tiene salida a internet. |
| **devsecops_net** | `backend`, `frontend`, `jenkins` | Comunicación entre app y herramientas. |
| **sonarnet** | `sonarqube`, `sonar-db` | SonarQube y su BD aislados; `sonar-db` no publica puertos. |

### Contenedores

- **security_opt: no-new-privileges:true** en todos los servicios (evita escalada de privilegios).
- **Puertos publicados solo en 127.0.0.1**: backend, frontend, Jenkins, SonarQube y la BD de la app; acceso solo desde el propio host.
- **tmpfs** en `/tmp` donde aplica para reducir escrituras en disco.
- **restart: unless-stopped** para que los servicios se reinicien de forma controlada.

### Aplicación

- **Backend (Spring Security):** cabeceras X-Content-Type-Options, X-Frame-Options (DENY), Content-Security-Policy; CORS restringido a orígenes concretos.
- **Frontend (Nginx, producción):** X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy.
- **Backend (imagen de producción):** ejecución como usuario no root (`appuser`).

### Credenciales

- Variables en `.env` (no en el código); existe `.env.example` como plantilla.
- En producción se recomienda usar contraseñas fuertes y distintas para cada servicio; opcionalmente Docker secrets.

---

## Estado de las conexiones

### Qué sí es seguro

| Aspecto | Situación |
|--------|-----------|
| **Cifrado en tránsito (mTLS BD ↔ Backend)** | El tráfico entre el backend Spring Boot y PostgreSQL viaja cifrado por TLS y autenticado mutuamente con certificados cliente y CA interna (`sslmode=verify-full`). |
| **Aislamiento de red** | Contenedores solo hablan dentro de sus redes; la BD de la app está en una red interna sin salida. |
| **Credenciales** | Inyectadas por `.env`; plantilla en `.env.example` sin valores reales. |
| **Binding a localhost** | Todos los puertos de acceso se publican en `127.0.0.1`. |
| **Privilegios** | `no-new-privileges`; imagen de producción del backend corre como usuario no root. |

### Qué no es seguro (limitaciones habituales en Docker)

| Aspecto | Situación |
|--------|-----------|
| **Tráfico en claro en otras herramientas** | El tráfico entre herramientas secundarias va en **texto claro** (TCP sin TLS). |
| **Autenticación en herramientas secundarias** | La comunicación entre las herramientas auxiliares se apoya en el aislamiento de la red Docker (`devsecops_net` / `sonarnet`). |

En entornos de **desarrollo o un solo host**, esto se suele aceptar porque la red Docker se considera “interna”. En **producción o varios hosts**, lo recomendable es cifrar en tránsito (TLS) y/o desplegar en una red aislada.

---

## Cómo mejorar la seguridad

### 1. No exponer bases de datos a la red del host (producción)

Si no necesitas conectar a PostgreSQL desde tu máquina (p. ej. con un cliente SQL), puedes **no publicar** el puerto de la base de datos. Solo los contenedores de la misma red podrán conectarse.

Ejemplo en `docker-compose.yml` (o en un override para producción):

```yaml
db:
  # ports:
  #   - '5432:5432'   # Comentar o quitar en producción
```

O publicar solo en localhost (ya aplicado en este proyecto para desarrollo):

```yaml
ports:
  - '127.0.0.1:5432:5432'
```

### 2. Cifrado mTLS para PostgreSQL (Implementado ✅)

El proyecto cuenta con autenticación y cifrado mutuo mTLS implementado entre el Backend Spring Boot y PostgreSQL/TimescaleDB.
- Se genera una CA raíz propia y certificados firmados con `./generate-certs.sh`.
- PostgreSQL exige `clientcert=verify-full`.
- El backend valida la CA y envía su certificado PKCS#8 en la URL JDBC:
  `jdbc:postgresql://db:5432/vulncheck?ssl=true&sslmode=verify-full&sslrootcert=/app/certs/ca.crt&sslcert=/app/certs/client.crt&sslkey=/app/certs/client.pk8`

Guía paso a paso y configuración completa: **[docs/MTLS_CONEXION_DB_BACKEND.md](MTLS_CONEXION_DB_BACKEND.md)**.

### 3. Cifrado en el borde (ingreso a la app)

Aunque el tráfico interno sea en claro, el acceso **desde el usuario** puede ir cifrado poniendo un **reverse proxy con TLS** (Traefik, Nginx, Caddy) delante del frontend/backend y terminando HTTPS ahí. Así el tráfico usuario → proxy sí va cifrado.

---

## Resumen

- **Desarrollo:** redes segmentadas, puertos en 127.0.0.1, `no-new-privileges`, cabeceras de seguridad y usuario no root en la imagen de producción del backend.
- **Producción:** no publicar puertos de BD si no hace falta, usar contraseñas fuertes (y `.env` o secrets), considerar TLS en PostgreSQL y/o reverse proxy con HTTPS.
