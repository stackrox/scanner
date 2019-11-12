package vulndump

import (
	"time"

	"github.com/stackrox/scanner/database"
)

// A WrappedVulnerability is a database.Vulnerability that is wrapped with a last updated time.
// It is used to save work on updates, to only write vulnerabilities that have actually changed.
type WrappedVulnerability struct {
	LastUpdatedTime time.Time              `json:"lastUpdatedTime"`
	Vulnerability   database.Vulnerability `json:"vulnerability"`
}
