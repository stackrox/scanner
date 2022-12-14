# cert

Scanner and ScannerDB requires valid certificates to run.
`gen-cert.sh` generates certificates for these deployments
and overwrites the current values in a given Kubernetes secret configuration file.

To run from the top-level directory and overwrite `chart/templates/mock-scanner[-db]-tls.yaml`:
```sh
./scripts/cert/gen-cert.sh chart/templates/mock-scanner-tls.yaml chart/templates/mock-scanner-db-tls.yaml
```
