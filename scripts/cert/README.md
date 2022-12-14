# cert

Scanner and ScannerDB requires valid certificates to run.
`gen-cert.sh` generates certificates for these deployments
and overwrites the current values in a given Kubernetes secret configuration file.

This script requires [`cfssl`](https://github.com/cloudflare/cfssl), which
may be installed via:
```sh
go install github.com/cloudflare/cfssl/cmd/...@latest
```

To run from the top-level directory and overwrite `chart/templates/mock-scanner[-db]-tls.yaml`:
```sh
./scripts/cert/gen-cert.sh chart/templates/mock-scanner-tls.yaml chart/templates/mock-scanner-db-tls.yaml
```
