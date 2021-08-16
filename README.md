# Scanner

![Red Hat Certified Image Scanner](img/Logo-Red_Hat-Certified_Technology-Vulnerability_Scanner-A-Red-RGB.png)

## To Build

### Prerequisites

  * [Make](https://www.gnu.org/software/make/)
  * [Go](https://golang.org/dl/)
    * Get the version specified in [go.mod](go.mod)
  * Various tools that can be installed with `make reinstall-dev-tools`.
    * Running the reinstall is especially important to do if you tend to switch between this and rox.

### Steps

If this is your first time, run the following:

```
$ make build-updater
$ ./bin/updater generate-dump --out-file image/scanner/dump/dump.zip
$ unzip image/scanner/dump/dump.zip -d image/scanner/dump
$ gsutil cp gs://stackrox-scanner-ci-vuln-dump/pg-definitions.sql.gz image/db/dump/definitions.sql.gz
$ make image
```

For any other time, just run `make image`.
