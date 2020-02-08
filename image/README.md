# RHEL based scanner and db images

The `scanner-rhel` and `scanner-db-rhel` images are defined in `scanner/rhel` and `db/rhel` used for the RedHat marketplace as well as for DoD customers.

These images are built in an opinionated way based on the DoD Centralized Artifacts Repository (DCAR) requirements outlined [here](https://dccscr.dsop.io/dsop/dccscr/tree/master/contributor-onboarding).

## Adding new files to the RHEL based images

To add a new file to a RHEL image, include it in `create-bundle.sh` script, do not add it to the Dockerfile in the `db/rhel` or `scanner/rhel` directories.
