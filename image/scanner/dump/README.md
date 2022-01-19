This directory contains all the vulnerability dumps (all untracked on Git).

There is a `genesis_manifests.json`, which outlines the metadata for all
genesis dumps we currently maintain. The format is as follows:

```json
{
  "knownGenesisDumps": [
    {
      "dumpLocationInGS": "Location of Genesis Dump in GCS (ie: gs://stackrox-scanner-ci-vuln-dump/genesis-YYYYMMDDHHMMSS.zip)",
      "timestamp": "'Until' time in the dump's manifest.json",
      "baseForOfflineDumps": true,
      "uuid": "UUID of the diff between the current state of vulns and the vulns embedded in the image from 'baseForOfflineDumps' (ie. gs://definitions.stackrox.io/<UUID>/diff.zip)",
      "config": {
        "skipFixableCentOSVulns": true,
        "ignoreKubernetesVulns": true
      }
    }
  ]
}
```

Only one entry in the `knownGenesisDumps` list may set `baseForOfflineDumps`.
When it is set to true, the dump located in the entry's `dumpLocationInGS` is used as
the de facto source of all vulnerabilities we track.

For any of the boolean settings, an omission is the same as `false`.
