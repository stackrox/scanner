# Scanner

![Red Hat Certified Image Scanner](img/Logo-Red_Hat-Certified_Technology-Vulnerability_Scanner-A-Red-RGB.png)

## Release Process

Scanner's release process does not have the same formalities as the rox repo at this time.
However, we continually work to improve it.

Every release for rox comes with a new Scanner release.

Scanner releases follow semantic versioning, and each new Scanner release updates the minor version (ie 2.x.0).
Only major, breaking changes will merit a bump to the major version, but this is unlikely to be the case in a normal release process.

### Creating a new Minor Release

1. Please follow the steps outlined [here](https://stack-rox.atlassian.net/wiki/spaces/ENGKB/pages/991363095/How+to+update+the+scanner+genesis+dump) to update the genesis dump
    * The purpose of this is to preload the latest version of Scanner with the most up-to-date vulnerability data
    * This severely decreases the startup time
1. Create a new branch `release/2.<new version>.x` based on the latest master once the genesis dump is updated
1. Create a new tag/release based on the new branch
1. Add release notes based on the changes between the previous release and this one
1. Once the latest image is built in CI, update the [SCANNER_VERSION](https://github.com/stackrox/rox/blob/master/SCANNER_VERSION) file in the rox repo

### Creating a new Path Release

1. Merge any updates into the `master` branch
1. Once merged, `git cherry-pick` the commit(s) into the relevant release branch(es)

Note: There is no genesis-dump update for patch releases (unless the patch, itself, requires it)

## How to Build

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
