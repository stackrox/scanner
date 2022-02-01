#! /bin/bash

rm -rf central-cert
mkdir central-cert


kubectl -n stackrox get secret central-tls -o json | jq -r '.data["cert.pem"] | @base64d' > central-cert/cert.pem
kubectl -n stackrox get secret central-tls -o json | jq -r '.data["key.pem"] | @base64d' > central-cert/key.pem

curl -k --cert central-cert/cert.pem --key central-cert/key.pem $@

rm -rf central-cert