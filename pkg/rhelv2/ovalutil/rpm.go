///////////////////////////////////////////////////
// Influenced by ClairCore under Apache 2.0 License
// https://github.com/quay/claircore
///////////////////////////////////////////////////

package ovalutil

import (
	"regexp"

	"github.com/pkg/errors"
	archop "github.com/quay/claircore"
	coreovalutil "github.com/quay/claircore/pkg/ovalutil"
	"github.com/quay/goval-parser/oval"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/database"
)

var moduleCommentRegex = regexp.MustCompile(`(Module )(.*)( is enabled)`)

// ProtoVulnFunc allows a caller to create a prototype vulnerability that will be
// copied and further defined for every applicable oval.Criterion discovered.
//
// This allows the caller to use oval.Definition fields and closure syntax when
// defining how a vulnerability should be parsed
type ProtoVulnFunc func(def oval.Definition) (*database.RHELv2Vulnerability, error)

// RPMDefsToVulns iterates over the definitions in an oval root and assumes RPMInfo objects and states.
//
// Each Criterion encountered with an EVR string will be translated into a database.RHELv2Vulnerability
func RPMDefsToVulns(root *oval.Root, protoVuln ProtoVulnFunc) ([]*database.RHELv2Vulnerability, error) {
	vulns := make([]*database.RHELv2Vulnerability, 0, 10000)
	var cris []*oval.Criterion
	for _, def := range root.Definitions.Definitions {
		// create our prototype vulnerability
		protoVuln, err := protoVuln(def)
		if err != nil {
			log.Warnf("Received error when parsing RHELv2 vulnerability. Skipping...: %v", err)
			continue
		}
		if protoVuln == nil {
			continue
		}
		// recursively collect criterions for this definition
		cris := cris[:0]
		walkCriterion(&def.Criteria, &cris)
		enabledModules := getEnabledModules(cris)
		if len(enabledModules) == 0 {
			// add default empty module
			enabledModules = append(enabledModules, "")
		}
		// unpack criterions into vulnerabilities
		for _, criterion := range cris {
			// if test object is not rmpinfo_test the provided test is not
			// associated with a package. this criterion will be skipped.
			test, err := coreovalutil.TestLookup(root, criterion.TestRef, func(kind string) bool {
				return kind == "rpminfo_test"
			})
			if err != nil {
				continue
			}

			objRefs := test.ObjectRef()
			stateRefs := test.StateRef()

			// from the rpminfo_test specification found here: https://oval.mitre.org/language/version5.7/ovaldefinition/documentation/linux-definitions-schema.html
			// "The required object element references a rpminfo_object and the optional state element specifies the data to check.
			//  The evaluation of the test is guided by the check attribute that is inherited from the TestType."
			//
			// thus we *should* only need to care about a single rpminfo_object and optionally a state object providing the package's fixed-in version.

			objRef := objRefs[0].ObjectRef
			object, err := rpmObjectLookup(root, objRef)
			if err != nil {
				continue
			}

			// state refs are optional, so this is not a requirement.
			// if a state object is discovered, we can use it to find
			// the "fixed-in-version"
			var state *oval.RPMInfoState
			if len(stateRefs) > 0 {
				stateRef := stateRefs[0].StateRef
				state, err = rpmStateLookup(root, stateRef)
				if err != nil {
					continue
				}
				// if we find a state, but this state does not contain an EVR,
				// we are not looking at a linux package.
				if state.EVR == nil {
					continue
				}
			}

			for _, module := range enabledModules {
				vuln := *protoVuln
				vuln.Package = &database.RHELv2Package{
					Name:   object.Name,
					Module: module,
				}
				if state != nil {
					vuln.FixedInVersion = state.EVR.Body
					if state.Arch != nil {
						vuln.ArchOperation = mapArchOp(state.Arch.Operation)
						vuln.Package.Arch = state.Arch.Body
					}
				}

				vulns = append(vulns, &vuln)
			}
		}
	}

	return vulns, nil
}

func mapArchOp(op oval.Operation) archop.ArchOp {
	switch op {
	case oval.OpEquals:
		return archop.OpEquals
	case oval.OpNotEquals:
		return archop.OpNotEquals
	case oval.OpPatternMatch:
		return archop.OpPatternMatch
	default:
	}
	return archop.ArchOp(0)
}

// walkCriterion recursively extracts Criterions from a root Criteria node in a depth
// first manor.
//
// a pointer to a slice header is modified in place when appending
func walkCriterion(node *oval.Criteria, cris *[]*oval.Criterion) {
	// recursive to leaves
	for _, criteria := range node.Criterias {
		walkCriterion(&criteria, cris)
	}
	// search for criterions at current node
	for _, criterion := range node.Criterions {
		c := criterion
		*cris = append(*cris, &c)
	}
}

func getEnabledModules(cris []*oval.Criterion) []string {
	var enabledModules []string
	for _, criterion := range cris {
		matches := moduleCommentRegex.FindStringSubmatch(criterion.Comment)
		if len(matches) > 2 && matches[2] != "" {
			moduleNameStream := matches[2]
			enabledModules = append(enabledModules, moduleNameStream)
		}
	}
	return enabledModules
}

func rpmObjectLookup(root *oval.Root, ref string) (*oval.RPMInfoObject, error) {
	kind, index, err := root.Objects.Lookup(ref)
	if err != nil {
		return nil, err
	}
	if kind != "rpminfo_object" {
		return nil, errors.Errorf("oval: got kind %q: skip this object", kind)
	}
	return &root.Objects.RPMInfoObjects[index], nil
}

func rpmStateLookup(root *oval.Root, ref string) (*oval.RPMInfoState, error) {
	kind, index, err := root.States.Lookup(ref)
	if err != nil {
		return nil, err
	}
	if kind != "rpminfo_state" {
		return nil, errors.Errorf("bad kind: %s", kind)
	}
	return &root.States.RPMInfoStates[index], nil
}
