package nvdloader

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
	"github.com/facebookincubator/nvdtools/vulndb"
	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	"github.com/stackrox/dotnet-scraper/types"
	"github.com/stackrox/scanner/pkg/ghsa"
)

// LoadGolangGHSA fetches Golang GHSA vuln data.
func LoadGolangGHSA(dir string, enrichmentMap map[string][]*FileFormatWrapper) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return errors.Wrap(err, "reading Golang GHSA directory")
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}

		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return errors.Wrapf(err, "reading file %s", entry.Name())
		}
		var advisory ghsa.AdvisoryWithVulnerabilities
		if err := yaml.Unmarshal(data, &advisory); err != nil {
			return errors.Wrapf(err, "unmarshaling yaml from file %s", entry.Name())
		}

		cveID, metadata, err := convertAdvisory(&advisory)
		if err != nil {
			return errors.Wrapf(err, "converting advisory data for %s", advisory.ID)
		}
		if cveID == "" {
			continue
		}
		enrichmentMap[cveID] = append(enrichmentMap[cveID], metadata)
	}

	return nil
}

func convertAdvisory(advisory *ghsa.AdvisoryWithVulnerabilities) (string, *FileFormatWrapper, error) {
	var cveID string
	for _, id := range advisory.Identifiers {
		if id.Type == "CVE" {
			cveID = id.Value
			break
		}
	}
	if cveID == "" {
		return "", nil, nil
	}

	ffw := &FileFormatWrapper{
		LastUpdated: advisory.UpdatedAt.Format(vulndb.TimeLayout),
		FileFormat: types.FileFormat{
			ID:   cveID,
			Link: advisory.Permalink,
		},
	}
	for _, vuln := range advisory.Vulnerabilities {
		affectedPackage := &schema.NVDCVEFeedJSON10DefCPEMatch{
			Cpe23Uri:   fmt.Sprintf("cpe:2.3:a:*:%s:*:*:*:*:*:*:*:*", strings.ReplaceAll(strings.ReplaceAll(vuln.Package.Name, "/", `\/`), ".", `\.`)),
			Vulnerable: true,
		}
		verRange, err := ghsa.ParseVersionRange(vuln.VulnerableVersionRange)
		if err != nil {
			return "", nil, errors.Wrapf(err, "unparseable version range in advisory %s", advisory.ID)
		}
		if verRange.MinVersion != "" {
			if verRange.MinVersionExclusive {
				affectedPackage.VersionStartExcluding = verRange.MinVersion
			} else {
				affectedPackage.VersionStartIncluding = verRange.MinVersion
			}
		}
		if verRange.MaxVersion != "" {
			if verRange.MaxVersionInclusive {
				affectedPackage.VersionEndIncluding = verRange.MaxVersion
			} else {
				affectedPackage.VersionEndExcluding = verRange.MaxVersion
			}
		}
		ffw.AffectedPackages = append(ffw.AffectedPackages, affectedPackage)
	}

	return cveID, ffw, nil
}
