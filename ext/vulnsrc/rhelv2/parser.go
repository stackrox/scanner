package rhelv2

import (
	"encoding/xml"
	"fmt"
	"github.com/stackrox/scanner/ext/vulnsrc/rhelv2/ovalutil"
	"github.com/stackrox/scanner/pkg/cpe"
	"io"
	"strings"

	"github.com/quay/goval-parser/oval"
	"github.com/stackrox/scanner/database"
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

		return &database.RHELv2Vulnerability{
			Name:               def.Title,
			Description:        def.Description,
			Issued:             def.Advisory.Issued.Date,
			Links:              links(def),
			Severity:           def.Advisory.Severity,
			CPEs: cpes,
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
