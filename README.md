# Scanner

![Red Hat Certified Image Scanner](img/Logo-Red_Hat-Certified_Technology-Vulnerability_Scanner-A-Red-RGB.png)

## Release Process

Scanner's release process does not have the same formalities as the rox repo at this time.
However, we continually work to improve it.

Every release for rox comes with a new Scanner release.

Scanner releases follow semantic versioning, and each new Scanner release updates the minor version (ie 2.x.0).
Only major, breaking changes will merit a bump to the major version, but this is unlikely to be the case in a normal release process.

### Creating a new Minor Release

1. Please follow the steps outlined [here](https://docs.engineering.redhat.com/display/ENGKB/How+to+update+the+scanner+genesis+dump) to update the genesis dump
    * The purpose of this is to preload the latest version of Scanner with the most up-to-date vulnerability data
    * This severely decreases the startup time
1. Create a new branch `release/2.<new version>.x` based on the latest master once the genesis dump is updated
1. Create a new tag/release based on the new branch
1. Add release notes based on the changes between the previous release and this one
1. Once the latest image is built in CI, update the [SCANNER_VERSION](https://github.com/stackrox/stackrox/blob/master/SCANNER_VERSION) file in the rox repo

### Creating a new Patch Release

1. Merge any updates into the `master` branch
1. Once merged, `git cherry-pick` the commit(s) into the relevant release branch(es)

Note: There is no genesis-dump update for patch releases (unless the patch, itself, requires it)

## Building

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

## Testing

There are various unit tests and bench tests scattered around the codebase.

On top of that, there are E2E tests defined in the `e2etests/` directory,
and there are some DB integration tests defined in `database/psql`.

### Unit Tests

To run these, simply run `make unit-tests`

### Bench Tests

There are several ways to run benchmarks. For the best results, run these tests via
the command line, as you will have more control over the settings.

To run go benchmarks, run the following:

```
// Run all benchmarks
$ go test -run=^$ -bench=. ./...

// Only run a specific benchmark for 2 minutes
$ go test -run=^$ -bench=^BenchmarkSpecific$ -benchtime=2m ./<PATH_TO_DIRECTORY_WITH_TEST>

// Gather profiles for specific benchmark
$ go test -run=^$ -bench=^BenchmarkSpecific$ -benchmem -memprofile memprofile.out -cpuprofile cpuprofile.out ./<PATH_TO_DIRECTORY_WITH_TEST>
```

### E2E Tests

E2E tests run in CI upon every commit. Sometimes,
changes are made which affect the genesis dumps. To test these,
simple add the `generate-dumps-on-pr` label to your PR.

### DB Integration Tests

DB integration tests also run in CI upon every commit.
However, to test these locally, be sure to [install PostgreSQL 12](https://postgresapp.com/downloads.html)
and run it prior to running the tests.
