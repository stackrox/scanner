package match

import (
	"github.com/facebookincubator/nvdtools/cvefeed"
	"github.com/facebookincubator/nvdtools/wfn"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/component"
)

type Result struct {
	CVE             cvefeed.Vuln
	CPE             wfn.AttributesWithFixedIn
	VersionOverride string
	Component       *component.Component
	Vuln            *database.Vulnerability
}
