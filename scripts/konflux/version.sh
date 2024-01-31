#!/bin/bash

# This script is used by the Konflux dockerfile to get the correct version to
# compile in to the binary.  If HEAD points to a git tag, use that; otherwise
# use `git describe ...`.

if [[ -n "$(git tag --contains)" ]]; then
    git tag --sort=creatordate --contains | tail -1
else
    git describe --tags --abbrev=10 --dirty --long
fi
