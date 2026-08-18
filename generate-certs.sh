#!/bin/bash
set -e

CERTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/certs"
mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

echo "[1/4] Generando Autoridad Certificadora (CA)..."
if [ ! -f ca.key ]; then
    openssl req -new -x509 -days 3650 -nodes \
        -out ca.crt -keyout ca.key \
        -subj "/CN=VulnChecker-CA/O=DevSecOps-USACH"
fi

echo "[2/4] Generando certificado de Servidor (PostgreSQL / TimescaleDB)..."
cat << 'EOF' > server_ext.cnf
[req]
distinguished_name = req_distinguished_name
req_extensions = req_ext
prompt = no

[req_distinguished_name]
CN = db

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = db
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

openssl req -new -nodes -out server.csr -keyout server.key -config server_ext.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365 -extfile server_ext.cnf -extensions req_ext
rm -f server.csr server_ext.cnf

echo "[3/4] Generando certificado de Cliente (Backend Spring Boot / vulnuser)..."
# CN debe coincidir con el usuario de la base de datos para autenticación cert
DB_USER="${DB_USERNAME:-vulnuser}"
cat << EOF > client_ext.cnf
[req]
distinguished_name = req_distinguished_name
req_extensions = req_ext
prompt = no

[req_distinguished_name]
CN = ${DB_USER}

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = backend
DNS.2 = vuln-backend
EOF

openssl req -new -nodes -out client.csr -keyout client.key -config client_ext.cnf
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt -days 365 -extfile client_ext.cnf -extensions req_ext
rm -f client.csr client_ext.cnf

echo "[4/4] Convirtiendo clave privada de cliente a formato PKCS#8 para JDBC..."
openssl pkcs8 -topk8 -inform PEM -outform DER -in client.key -out client.pk8 -nocrypt

# Ajustar permisos exigidos por PostgreSQL y seguridad
chmod 600 server.key client.key client.pk8 ca.key
chmod 644 server.crt client.crt ca.crt

echo " Certificados generados exitosamente en $CERTS_DIR"
