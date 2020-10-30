package vulndump

import (
	"time"
)

// This block enumerates the files/directories in the vuln dump.
// The vuln dump itself is a zip with all these directories.
const (
	ManifestFileName = "manifest.json"
	OSVulnsFileName  = "os_vulns.json"
	NVDDirName       = "nvd"
	RedHatDirName    = "redhat"
	K8sDirName       = "k8s"
)

// Manifest is used to JSON marshal/unmarshal the manifest.json file.
type Manifest struct {
	Since time.Time `json:"since"`
	Until time.Time `json:"until"`
}
