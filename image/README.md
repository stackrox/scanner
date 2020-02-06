# RedHat Based scanner and db images

The RedHat based scanner and db images are currently used for the RedHat marketplace as well as for DoD customers.

These images are built in an opinionated way based on the DoD Centralized Artifacts Repository (DCAR) requirements outlined [here](https://dccscr.dsop.io/dsop/dccscr/tree/master/contributor-onboarding).

## Adding new files to the rhel based images

To add a new file to the rhel image, include it in `create-bundle.sh` script, do not add it to the Dockerfile in this directory.
