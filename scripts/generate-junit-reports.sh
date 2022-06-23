#!/usr/bin/env bash

# Copied from https://github.com/stackrox/stackrox/blob/master/scripts/generate-junit-reports.sh

mkdir -p junit-reports

go-junit-report <"test-output/test.log" >"junit-reports/report.xml"
