#!/usr/bin/env bash

## This script generates new certs for Scanner and Scanner DB used by CI.

set -e

SCANNER_TLS_FILE=$1
SCANNER_DB_TLS_FILE=$2

SED_ARG="-i"
UNAME=$(uname -s)
if [ ${UNAME} == "Darwin" ]; then
    SED_ARG="-i ''"
fi

echo "Generating CA and Cert/Key for Scanner"
cfssl genkey -initca scanner-csr.json | cfssljson -bare ca
SCANNER_CA=$(base64 -in ca.pem)
cfssl gencert -ca ca.pem -ca-key ca-key.pem scanner-csr.json | cfssljson -bare
SCANNER_CERT=$(base64 -in cert.pem)
SCANNER_KEY=$(base64 -in cert-key.pem)
yq eval ".data[\"ca.pem\"] = \"${SCANNER_CA}\"" ${SCANNER_TLS_FILE} > tmp.yaml
yq eval ".data[\"cert.pem\"] = \"${SCANNER_CERT}\"" tmp.yaml > tmp2.yaml
yq eval ".data[\"key.pem\"] = \"${SCANNER_KEY}\"" tmp2.yaml > tmp3.yaml
mv tmp3.yaml ${SCANNER_TLS_FILE}

rm -f *.pem *.csr *.yaml

echo "Generating CA and Cert/Key for Scanner DB"
cfssl genkey -initca scanner-db-csr.json | cfssljson -bare ca
SCANNER_DB_CA=$(base64 -in ca.pem)
cfssl gencert -ca ca.pem -ca-key ca-key.pem scanner-db-csr.json | cfssljson -bare
SCANNER_DB_CERT=$(base64 -in cert.pem)
SCANNER_DB_KEY=$(base64 -in cert-key.pem)
yq eval ".data[\"ca.pem\"] = \"${SCANNER_DB_CA}\"" ${SCANNER_DB_TLS_FILE} > tmp.yaml
yq eval ".data[\"cert.pem\"] = \"${SCANNER_DB_CERT}\"" tmp.yaml > tmp2.yaml
yq eval ".data[\"key.pem\"] = \"${SCANNER_DB_KEY}\"" tmp2.yaml > tmp3.yaml
mv tmp3.yaml ${SCANNER_DB_TLS_FILE}

rm -f *.pem *.csr *.yaml
