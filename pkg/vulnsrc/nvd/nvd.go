package nvd

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/stackrox/scanner/pkg/types"
)

var(
	extensionRegex = regexp.MustCompile(`\.(RELEASE|GA|SEC.*)$`)
	numRegex = regexp.MustCompile(`[0-9].*$`)
)

type cpeKey struct {
	vendor, name, version string
}

type NVD struct {
	CPEToVulns map[cpeKey]map[string]struct{}
}

func NewNVD(path string) (*NVD, error) {
	cpeToVulns, err := GetCPEData(path)
	if err != nil {
		return nil, err
	}
	return &NVD{
		CPEToVulns: cpeToVulns,
	}, nil
}

type set map[string]interface{}

func newSet() set {
	return make(map[string]interface{})
}

func (s set) Add(k string) {
	s[k] = struct{}{}
}

func getCPEKeysForJava(comp *types.Component) []cpeKey {
	versionSet := newSet()
	if comp.JavaPackage.ImplementationVersion != "" {
		versionSet.Add(comp.JavaPackage.ImplementationVersion)
	}
	if comp.JavaPackage.MavenVersion  != "" {
		versionSet.Add(comp.JavaPackage.MavenVersion)
	}
	if comp.JavaPackage.SpecificationVersion  != "" {
		versionSet.Add(comp.JavaPackage.SpecificationVersion)
	}
	for k := range versionSet {
		versionSet.Add(extensionRegex.ReplaceAllString(k, ""))
	}

	nameSet := newSet()
	nameSet.Add(comp.JavaPackage.Name)
	nameSet.Add(strings.ReplaceAll(comp.JavaPackage.Name, "_", "-"))
	nameSet.Add(strings.ReplaceAll(comp.JavaPackage.Name, "-", "_"))
	nameSet.Add(numRegex.ReplaceAllString(comp.JavaPackage.Name, ""))

	for name := range nameSet {
		if idx := strings.Index(name, "-"); idx != -1 {
			nameSet.Add(name[:idx])
		}
	}

	var vendor string
	originSpl := strings.Split(comp.JavaPackage.Origin, ".")
	// This is probably pretty fragile
	if len(originSpl) == 3 {
		vendor = originSpl[1]
	}

	var cpeKeys []cpeKey
	for name := range nameSet {
		for version := range versionSet {
			cpeKeys = append(cpeKeys, cpeKey{vendor: vendor, name: name, version: version})
		}
	}
	return cpeKeys
}

func (n *NVD) EvaluateJava(comp *types.Component) []string {
	cpeKeys := getCPEKeysForJava(comp)

	var vulns []string
	for _, c := range cpeKeys {
		for vuln := range n.CPEToVulns[c] {
			vulns = append(vulns, vuln)
		}
	}
	return vulns
}

func (n *NVD) EvaluateForVulns(comp *types.Component) []string {
	switch comp.Type {
	case types.JAR:
		return n.EvaluateJava(comp)
	default:
		panic(fmt.Sprintf("unsupported component type: %T", comp.Type))
	}
}
