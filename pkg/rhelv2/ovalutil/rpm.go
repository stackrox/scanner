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

const (
	// CVEDefinition indicates the vulnerability definition is for a CVE.
	CVEDefinition = "cve"
	// RHBADefinition indicates the vulnerability definition is for a RHBA.
	RHBADefinition = "rhba"
	// RHEADefinition indicates the vulnerability definition is for a RHEA.
	RHEADefinition = "rhea"
	// RHSADefinition indicates the vulnerability definition is for a RHSA.
	RHSADefinition = "rhsa"
	// UnaffectedDefinition indicates the vulnerability definition is for
	// a package that is unaffected by the CVE.
	UnaffectedDefinition = "unaffected"
)

var (
	moduleCommentRegex  = regexp.MustCompile(`(Module )(.*)( is enabled)`)
	definitionTypeRegex = regexp.MustCompile(`^oval:com\.redhat\.([a-z]+):def:\d+$`)

	errObjectUnnamed = errors.New("oval: rpminfo_object does not have a name: skip this object")
)

// ProtoVulnFunc allows a caller to create a prototype vulnerability that will be
// copied and further defined for every applicable oval.Criterion discovered.
//
// This allows the caller to use oval.Definition fields and closure syntax when
// defining how a vulnerability should be parsed
type ProtoVulnFunc func(def oval.Definition) (*database.RHELv2Vulnerability, error)

type criterionWithModule struct {
	*oval.Criterion
	module string
}

// RPMDefsToVulns iterates over the definitions in an oval root and assumes RPMInfo objects and states.
//
// Each Criterion encountered with an EVR string will be translated into a database.RHELv2Vulnerability
func RPMDefsToVulns(root *oval.Root, protoVuln ProtoVulnFunc) ([]*database.RHELv2Vulnerability, error) {
	vulns := make([]*database.RHELv2Vulnerability, 0, 10000)
	var cris []*criterionWithModule
	for _, def := range root.Definitions.Definitions {
		// create our prototype vulnerability
		vuln, err := protoVuln(def)
		if err != nil {
			log.Errorf("Received error when parsing RHELv2 vulnerability: %v", err)
			return nil, err
		}
		if vuln == nil {
			continue
		}
		// recursively collect criterions for this definition

		cris := cris[:0]
		walkCriterion("", &def.Criteria, &cris)
		// unpack criterions into vulnerabilities
		for _, criterion := range cris {
			// if test object is not rpminfo_test the provided test is not
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
				if err == errObjectUnnamed {
					log.Errorf("Object ref %s for criterion %s for vuln %s is unnamed. Skipping...", objRef, criterion.Comment, vuln.Name)
				}
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

			pkgInfo := &database.RHELv2PackageInfo{}
			if state != nil {
				pkgInfo.FixedInVersion = state.EVR.Body
				if state.Arch != nil {
					pkgInfo.ArchOperation = mapArchOp(state.Arch.Operation)
				}
			}

			if pkgInfo.FixedInVersion == "" {
				// Title is used only as supplementary to FixedInVersion without a patch number.
				// If FixedInVersion is not defined, we keep the title empty to reduce the scale of the database.
				vuln.Title = ""
			}
			pkg := &database.RHELv2Package{
				// object.Name will never be empty.
				Name:   object.Name,
				Module: criterion.module,
			}
			if state != nil && state.Arch != nil {
				pkg.Arch = state.Arch.Body
			}

			pkgInfo.Packages = append(pkgInfo.Packages, pkg)

			vuln.PackageInfos = append(vuln.PackageInfos, pkgInfo)
		}

		vulns = append(vulns, vuln)
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
// first manner.
//
// a pointer to a slice header is modified in place when appending
func walkCriterion(module string, node *oval.Criteria, cris *[]*criterionWithModule) {
	// search for criterions at current node
	for _, criterion := range node.Criterions {
		c := criterion
		if foundModule, ok := moduleFromCriterion(&c); ok {
			module = foundModule
		}
		*cris = append(*cris, &criterionWithModule{Criterion: &c, module: module})
	}

	// recursive to leaves
	for _, criteria := range node.Criterias {
		walkCriterion(module, &criteria, cris)
	}
}

func moduleFromCriterion(criterion *oval.Criterion) (string, bool) {
	matches := moduleCommentRegex.FindStringSubmatch(criterion.Comment)
	if len(matches) > 2 && matches[2] != "" {
		return matches[2], true
	}
	return "", false
}

func rpmObjectLookup(root *oval.Root, ref string) (*oval.RPMInfoObject, error) {
	kind, index, err := root.Objects.Lookup(ref)
	if err != nil {
		return nil, err
	}
	if kind != "rpminfo_object" {
		return nil, errors.Errorf("oval: got kind %q: skip this object", kind)
	}
	obj := &root.Objects.RPMInfoObjects[index]
	if obj.Name == "" {
		return nil, errObjectUnnamed
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

// GetDefinitionType parses an OVAL definition and extracts its type from ID.
func GetDefinitionType(def oval.Definition) (string, error) {
	match := definitionTypeRegex.FindStringSubmatch(def.ID)
	if len(match) != 2 { // we should have match of the whole string and one submatch
		return "", errors.New("cannot parse definition ID for its type")
	}
	return match[1], nil
}
