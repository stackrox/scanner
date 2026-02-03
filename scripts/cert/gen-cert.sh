#!/usr/bin/env bash

## This script generates new certs for Scanner and Scanner DB used by CI.

set -e

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"

SCANNER_TLS_FILE=$1
SCANNER_DB_TLS_FILE=$2

echo "Generating CA for Scanner and Scanner DB"
cfssl genkey -initca "$ROOT/scripts/cert/csr.json" | cfssljson -bare ca
SCANNER_CA=$(base64 -i ca.pem)

echo "Generating Cert/Key pair for Scanner"
cfssl gencert -ca ca.pem -ca-key ca-key.pem -hostname scanner.stackrox "$ROOT/scripts/cert/csr.json" | cfssljson -bare
SCANNER_CERT=$(base64 -i cert.pem)
SCANNER_KEY=$(base64 -i cert-key.pem)
yq eval ".data[\"ca.pem\"] = \"${SCANNER_CA}\"" "${SCANNER_TLS_FILE}" > tmp.yaml
yq eval ".data[\"cert.pem\"] = \"${SCANNER_CERT}\"" tmp.yaml > tmp2.yaml
yq eval ".data[\"key.pem\"] = \"${SCANNER_KEY}\"" tmp2.yaml > tmp3.yaml
mv tmp3.yaml "${SCANNER_TLS_FILE}"

rm -f tmp.yaml tmp2.yaml

echo "Generating Cert/Key pair for Scanner DB"
cfssl gencert -ca ca.pem -ca-key ca-key.pem -hostname scanner-db.stackrox "$ROOT/scripts/cert/csr.json" | cfssljson -bare
SCANNER_DB_CERT=$(base64 -i cert.pem)
SCANNER_DB_KEY=$(base64 -i cert-key.pem)
yq eval ".data[\"ca.pem\"] = \"${SCANNER_CA}\"" "${SCANNER_DB_TLS_FILE}" > tmp.yaml
yq eval ".data[\"cert.pem\"] = \"${SCANNER_DB_CERT}\"" tmp.yaml > tmp2.yaml
yq eval ".data[\"key.pem\"] = \"${SCANNER_DB_KEY}\"" tmp2.yaml > tmp3.yaml
mv tmp3.yaml "${SCANNER_DB_TLS_FILE}"

rm -f *.pem *.csr tmp.yaml tmp2.yaml
