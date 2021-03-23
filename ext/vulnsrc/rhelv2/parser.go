package rhelv2

import (
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/quay/goval-parser/oval"
	"github.com/stackrox/rox/pkg/stringutils"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/vulnsrc/rhelv2/ovalutil"
	"github.com/stackrox/scanner/pkg/cpe"
)

func parse(release Release, r io.Reader) ([]*database.RHELv2Vulnerability, error) {
	var root oval.Root
	if err := xml.NewDecoder(r).Decode(&root); err != nil {
		return nil, fmt.Errorf("rhelv2: unable to decode OVAL document: %w", err)
	}

	protoVuln := func(def oval.Definition) (*database.RHELv2Vulnerability, error) {
		cpes := make([]cpe.WFN, 0, len(def.Advisory.AffectedCPEList))
		for _, affected := range def.Advisory.AffectedCPEList {
			// Work around having empty entries. This seems to be some issue
			// with the tool used to produce the database but only seems to
			// appear sometimes, like RHSA-2018:3140 in the rhel-7-alt database.
			if affected == "" {
				continue
			}

			wfn, err := cpe.Unbind(affected)
			if err != nil {
				return nil, err
			}

			cpes = append(cpes, wfn)
		}

		if len(cpes) == 0 {
			return nil, nil
		}

		var cvss3, cvss2 database.CVSS
		// For CVEs, there will only be 1 element in this slice.
		// For RHSAs, RHBAs, etc, there will typically be 1 or more.
		// As we have done in the past, we will take the maximum score.
		for _, cve := range def.Advisory.Cves {
			if cve.Cvss3 != "" {
				scoreStr, vector := stringutils.Split2(cve.Cvss3, "/")
				score, err := strconv.ParseFloat(scoreStr, 64)
				if err != nil {
					return nil, errors.Wrapf(err, "Unable to parse CVSS3 for vuln %s: %s", def.Title, scoreStr)
				}
				if score > cvss3.Score {
					cvss3.Score = score
					cvss3.Vector = vector
				}
			}

			if cve.Cvss2 != "" {
				scoreStr, vector := stringutils.Split2(cve.Cvss2, "/")
				score, err := strconv.ParseFloat(scoreStr, 64)
				if err != nil {
					return nil, errors.Wrapf(err, "Unable to parse CVSS2 for vuln %s: %s", def.Title, scoreStr)
				}
				if score > cvss2.Score {
					cvss2.Score = score
					cvss2.Vector = vector
				}
			}
		}

		return &database.RHELv2Vulnerability{
			Name:        def.Title,
			Description: def.Description,
			Issued:      def.Advisory.Issued.Date,
			Links:       links(def),
			Severity:    def.Advisory.Severity,
			CVSSv3:      cvss3,
			CVSSv2:      cvss2,
			CPEs:        cpes,
			// each updater is configured to parse a rhel release
			// specific xml database. we'll use the updater's release
			// to map the parsed vulnerabilities
			Distribution: releaseToDist(release),
		}, nil
	}
	vulns, err := ovalutil.RPMDefsToVulns(&root, protoVuln)
	if err != nil {
		return nil, err
	}
	return vulns, nil
}

// links joins all the links in the cve definition into a single string.
func links(definition oval.Definition) string {
	ls := []string{}

	for _, ref := range definition.References {
		ls = append(ls, ref.RefURL)
	}

	for _, ref := range definition.Advisory.Refs {
		ls = append(ls, ref.URL)
	}
	for _, bug := range definition.Advisory.Bugs {
		ls = append(ls, bug.URL)
	}

	return strings.Join(ls, " ")
}
