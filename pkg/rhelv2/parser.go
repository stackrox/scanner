///////////////////////////////////////////////////
// Influenced by ClairCore under Apache 2.0 License
// https://github.com/quay/claircore
///////////////////////////////////////////////////

package rhelv2

import (
	"encoding/xml"
	"fmt"
	"io"
	"strconv"

	"github.com/pkg/errors"
	"github.com/quay/goval-parser/oval"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/rox/pkg/stringutils"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/cpe"
	"github.com/stackrox/scanner/pkg/cpeutils"
	"github.com/stackrox/scanner/pkg/rhelv2/ovalutil"
)

func isValidCPE(cpeSet set.StringSet, cpe string) bool {
	return cpeutils.IsOpenShiftCPE(cpe) || cpeSet.Contains(cpe)
}

func isSkippableDefType(defType ovalutil.DefinitionType) bool {
	return defType == ovalutil.UnaffectedDefinition || defType == ovalutil.NoneDefinition
}

func parse(cpeSet set.StringSet, uri string, r io.Reader) ([]*database.RHELv2Vulnerability, error) {
	var root oval.Root
	if err := xml.NewDecoder(r).Decode(&root); err != nil {
		return nil, fmt.Errorf("rhelv2: unable to decode OVAL document at %s: %w", uri, err)
	}

	protoVuln := func(def oval.Definition) (*database.RHELv2Vulnerability, error) {
		defType, err := ovalutil.GetDefinitionType(def)
		if err != nil {
			return nil, err
		}

		// Red Hat OVAL v2 data include information about vulnerabilities,
		// that actually don't affect the package in any way. Storing them
		// would increase number of records in DB without adding any value.
		if isSkippableDefType(defType) {
			return nil, nil
		}

		name := name(def)
		if name == "" {
			return nil, errors.Errorf("Unable to determine name of vuln %q in %s", def.Title, uri)
		}

		// This is the typical case: each listed CPE maps to a single CPE
		// associated with the vulnerability.
		// However, unpatched OpenShift 4 vulnerabilities are different.
		// See below for more information.
		cpes := make([]string, 0, len(def.Advisory.AffectedCPEList))

		for _, affected := range def.Advisory.AffectedCPEList {
			// Work around having empty entries. This seems to be some issue
			// with the tool used to produce the database but only seems to
			// appear sometimes, like RHSA-2018:3140 in the rhel-7-alt database.
			if affected == "" || !isValidCPE(cpeSet, affected) {
				continue
			}

			// Ensure CPE's validity.
			_, err := cpe.Unbind(affected)
			if err != nil {
				return nil, err
			}

			// If this is an unfixed OpenShift 4.x vulnerability, add a CPE for each minor version
			// below the given minor version. If there is no given minor version, a default is used.
			// There is only a single OVAL v2 file for all OpenShift 4 versions,
			// so it is assumed the CPE specified for the vulnerability indicates
			// versions x such that 4.0 <= y <= 4.x are affected, where x is the specified OpenShift 4 minor version
			// (or a default, if no version is given).
			// It is expected the CPE is of the form cpe:/a:redhat:openshift:4.x, cpe:/a:redhat:openshift:4.x::el8,
			// cpe:/a:redhat:openshift:4, or cpe:/a:redhat:openshift:4::el8.
			// Any other OpenShift 4-related CPEs are not supported at this time.
			if defType == ovalutil.CVEDefinition && cpeutils.IsOpenShift4CPE(affected) {
				if openshiftCPEs, err := cpeutils.GetAllOpenShift4CPEs(affected); err != nil {
					log.Warnf("Skipping addition of extra OpenShift 4 CPEs for the unpatched vulnerability %q: %v", name, err)
				} else {
					cpes = append(cpes, openshiftCPEs...)
				}
			} else {
				// Add the given CPE to the slice.
				cpes = append(cpes, affected)
			}
		}

		if len(cpes) == 0 {
			return nil, nil
		}

		var cvss3, cvss2 struct {
			score  float64
			vector string
		}
		// For CVEs, there will only be 1 element in this slice.
		// For RHSAs, RHBAs, etc, there will typically be 1 or more.
		// As we have done in the past, we will take the maximum score.
		var subCVEs []string
		for _, cve := range def.Advisory.Cves {
			if cve.Cvss3 != "" {
				scoreStr, vector := stringutils.Split2(cve.Cvss3, "/")
				score, err := strconv.ParseFloat(scoreStr, 64)
				if err != nil {
					return nil, errors.Wrapf(err, "Unable to parse CVSS3 for vuln %s: %s", def.Title, scoreStr)
				}
				if score > cvss3.score {
					cvss3.score = score
					cvss3.vector = vector
				}
			}

			if cve.Cvss2 != "" {
				scoreStr, vector := stringutils.Split2(cve.Cvss2, "/")
				score, err := strconv.ParseFloat(scoreStr, 64)
				if err != nil {
					return nil, errors.Wrapf(err, "Unable to parse CVSS2 for vuln %s: %s", def.Title, scoreStr)
				}
				if score > cvss2.score {
					cvss2.score = score
					cvss2.vector = vector
				}
			}
			if IsRedHatAdvisory(name) {
				subCVEs = append(subCVEs, cve.CveID)
			}
		}

		var cvss3Str, cvss2Str string
		if cvss3.score > 0 && cvss3.vector != "" {
			cvss3Str = fmt.Sprintf("%.1f/%s", cvss3.score, cvss3.vector)
		}
		if cvss2.score > 0 && cvss2.vector != "" {
			cvss2Str = fmt.Sprintf("%.1f/%s", cvss2.score, cvss2.vector)
		}

		link := link(def)
		if link == "" {
			// Log as a warning, as this is not critical, but it is good to know.
			log.Warnf("Unable to determine link for vuln %q in %s", def.Title, uri)
		}

		return &database.RHELv2Vulnerability{
			Name:        name,
			Title:       def.Title,
			Description: def.Description,
			Issued:      def.Advisory.Issued.Date,
			Updated:     def.Advisory.Updated.Date,
			Link:        link,
			Severity:    def.Advisory.Severity,
			CVSSv3:      cvss3Str,
			CVSSv2:      cvss2Str,
			CPEs:        cpes,
			SubCVEs:     subCVEs,
		}, nil
	}
	vulns, err := ovalutil.RPMDefsToVulns(&root, protoVuln)
	if err != nil {
		return nil, err
	}
	return vulns, nil
}

// name gets the RHSA/RHBA ID from the given definition.
func name(definition oval.Definition) string {
	if len(definition.References) > 0 {
		return definition.References[0].RefID
	}

	return ""
}

// link gets the relevant URL for the vulnerability.
func link(definition oval.Definition) string {
	if len(definition.References) > 0 {
		return definition.References[0].RefURL
	}

	return ""
}
