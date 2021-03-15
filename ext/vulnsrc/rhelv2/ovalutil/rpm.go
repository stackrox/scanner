package ovalutil

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/quay/goval-parser/oval"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/vulnsrc/rhelv2/archop"
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
// Each Criterion encountered with an EVR string will be translated into a claircore.Vulnerability
func RPMDefsToVulns(root *oval.Root, protoVuln ProtoVulnFunc) ([]*database.RHELv2Vulnerability, error) {
	vulns := make([]*database.RHELv2Vulnerability, 0, 10000)
	cris := []*oval.Criterion{}
	for _, def := range root.Definitions.Definitions {
		// create our prototype vulnerability
		protoVuln, err := protoVuln(def)
		if err != nil || protoVuln == nil {
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
			test, err := TestLookup(root, criterion.TestRef, func(kind string) bool {
				return kind == "rpminfo_test"
			})
			switch {
			case errors.Is(err, nil):
			case errors.Is(err, errTestSkip):
				continue
			default:
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
			switch {
			case errors.Is(err, nil):
			case errors.Is(err, errObjectSkip):
				// We only handle rpminfo_objects.
				continue
			default:
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
				vuln.Package = &database.Package{
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

// walkCriterion recursively extracts Criterions from a root Crteria node in a depth
// first manor.
//
// a pointer to a slice header is modified in place when appending
func walkCriterion(node *oval.Criteria, cris *[]*oval.Criterion) {
	// recursive to leafs
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
	enabledModules := []string{}
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
		return nil, fmt.Errorf("oval: got kind %q: %w", kind, errObjectSkip)
	}
	return &root.Objects.RPMInfoObjects[index], nil
}

func rpmStateLookup(root *oval.Root, ref string) (*oval.RPMInfoState, error) {
	kind, index, err := root.States.Lookup(ref)
	if err != nil {
		return nil, err
	}
	if kind != "rpminfo_state" {
		return nil, fmt.Errorf("bad kind: %s", kind)
	}
	return &root.States.RPMInfoStates[index], nil
}
