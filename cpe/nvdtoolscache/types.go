package nvdtoolscache

import (
	"fmt"

	"github.com/stackrox/scanner/database"
)

type Vuln struct {
	ID       string
	Metadata *Metadata
	Summary  string
}

type Metadata struct {
	PublishedDateTime    string
	LastModifiedDateTime string
	CVSSv2               MetadataCVSSv2
	CVSSv3               MetadataCVSSv3
}

type MetadataCVSSv2 struct {
	Vectors             string
	Score               float64
	ExploitabilityScore float64
	ImpactScore         float64
}

type MetadataCVSSv3 struct {
	Vectors             string
	Score               float64
	ExploitabilityScore float64
	ImpactScore         float64
}

func (v *Vuln) Vulnerability() *database.Vulnerability {
	return &database.Vulnerability{
		Name:        v.ID,
		Description: v.Summary,
		Link:        fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", v.ID),
		Metadata: map[string]interface{}{
			"NVD": v.Metadata,
		},
	}
}
