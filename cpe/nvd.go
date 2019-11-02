package cpe

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-version"
	"github.com/stackrox/scanner/database"
)

var (
	cpeMatcher = make(map[vendorNamePair][]*vulnMatcher)
)

type vendorNamePair struct {
	vendor, name string
}

type vulnMatcher struct {
	item              *Item
	constraintMatcher constraintMatcher
	fixedVersion      string
}

func (m *vulnMatcher) Matches(s string) *database.Vulnerability {
	if m.constraintMatcher(s) {
		vuln := m.item.Vulnerability()
		vuln.FixedBy = m.fixedVersion
		return vuln
	}
	return nil
}

type Matcher interface {
	Matches(s string) *database.Vulnerability
}

func handleJSONFile(path string) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	var data NVDData
	if err := json.Unmarshal(bytes, &data); err != nil {
		panic(err)
	}

	for _, item := range data.Items {
		for _, node := range item.Configuration.Nodes {
			pairs := recurseNode(node)
			for _, p := range pairs {
				vulnMatcher := &vulnMatcher{
					item:              item,
					constraintMatcher: p.constraint,
					fixedVersion:      p.fixedVersion,
				}

				vendorPair := vendorNamePair{vendor: p.vendor, name: p.name}
				cpeMatcher[vendorPair] = append(cpeMatcher[vendorPair], vulnMatcher)

				vendorLessPair := vendorNamePair{name: p.name}
				cpeMatcher[vendorLessPair] = append(cpeMatcher[vendorLessPair], vulnMatcher)
			}
		}
		// Mark configuration as nil so it can be garbage collected
		item.Configuration = nil
	}
}

func init() {
	definitionsDir := os.Getenv("NVD_DEFINITIONS_DIR")
	if definitionsDir == "" {
		return
	}

	extractedPath := filepath.Join(definitionsDir, "cve")
	files, err := ioutil.ReadDir(extractedPath)
	if err != nil {
		fmt.Printf("Error extracting files: %q\n", extractedPath)
		return
	}

	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		handleJSONFile(filepath.Join(extractedPath, f.Name()))
	}
}

type CVEDataMeta struct {
	ID string
}

type Description struct {
	DescriptionData []DescriptionItem `json:"description_data"`
}

type DescriptionItem struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type CVE struct {
	CVEDataMeta *CVEDataMeta `json:"CVE_data_meta"`
	Description Description  `json:"description"`
}

type Match struct {
	Vulnerable            bool   `json:"vulnerable"`
	CPE23URI              string `json:"cpe23Uri"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionStartIncluding string `json:"versionStartIncluding"`
}

type Node struct {
	Children []*Node  `json:"children"`
	Operator string   `json:"operator"`
	CPEMatch []*Match `json:"cpe_match"`
}

type Configuration struct {
	Nodes []*Node `json:"nodes"`
}

type Item struct {
	Impact               Impact         `json:"impact"`
	CVE                  *CVE           `json:"cve"`
	Configuration        *Configuration `json:"configurations"`
	PublishedDateTime    string         `json:"publishedDate"`
	LastModifiedDateTime string         `json:"lastModifiedDate"`
}

type Impact struct {
	BaseMetricV2 BaseMetricV2 `json:"baseMetricV2"`
	BaseMetricV3 BaseMetricV3 `json:"baseMetricV3"`
}

type BaseMetricV2 struct {
	CVSSv2              CVSSv2  `json:"cvssV2"`
	ExploitabilityScore float64 `json:"exploitabilityScore"`
	ImpactScore         float64 `json:"impactScore"`
}

type CVSSv2 struct {
	Score            float64 `json:"baseScore"`
	AccessVector     string  `json:"accessVector"`
	AccessComplexity string  `json:"accessComplexity"`
	Authentication   string  `json:"authentication"`
	ConfImpact       string  `json:"confidentialityImpact"`
	IntegImpact      string  `json:"integrityImpact"`
	AvailImpact      string  `json:"availabilityImpact"`
}

type BaseMetricV3 struct {
	CVSSv3              CVSSv3  `json:"cvssV3"`
	ExploitabilityScore float64 `json:"exploitabilityScore"`
	ImpactScore         float64 `json:"impactScore"`
}

type CVSSv3 struct {
	Score              float64 `json:"baseScore"`
	AttackVector       string  `json:"attackVector"`
	AttackComplexity   string  `json:"attackComplexity"`
	PrivilegesRequired string  `json:"privilegesRequired"`
	UserInteraction    string  `json:"userInteraction"`
	Scope              string  `json:"scope"`
	ConfImpact         string  `json:"confidentialityImpact"`
	IntegImpact        string  `json:"integrityImpact"`
	AvailImpact        string  `json:"availabilityImpact"`
}

var vectorValuesToLetters = map[string]string{
	"NETWORK":          "N",
	"ADJACENT_NETWORK": "A",
	"LOCAL":            "L",
	"HIGH":             "H",
	"MEDIUM":           "M",
	"LOW":              "L",
	"NONE":             "N",
	"SINGLE":           "S",
	"MULTIPLE":         "M",
	"PARTIAL":          "P",
	"COMPLETE":         "C",

	// CVSSv3 only
	"PHYSICAL":  "P",
	"REQUIRED":  "R",
	"CHANGED":   "C",
	"UNCHANGED": "U",
}

type NVDData struct {
	Items []*Item `json:"CVE_Items"`
}

func (i *Item) Summary() string {
	for _, desc := range i.CVE.Description.DescriptionData {
		if desc.Lang == "en" {
			return desc.Value
		}
	}
	return ""
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

func (i *Item) Metadata() *Metadata {
	if i.Impact.BaseMetricV2.CVSSv2.String() == "" {
		return nil
	}
	metadata := &Metadata{
		PublishedDateTime:    i.PublishedDateTime,
		LastModifiedDateTime: i.LastModifiedDateTime,
		CVSSv2: MetadataCVSSv2{
			Vectors:             i.Impact.BaseMetricV2.CVSSv2.String(),
			Score:               i.Impact.BaseMetricV2.CVSSv2.Score,
			ExploitabilityScore: i.Impact.BaseMetricV2.ExploitabilityScore,
			ImpactScore:         i.Impact.BaseMetricV2.ImpactScore,
		},
		CVSSv3: MetadataCVSSv3{
			Vectors:             i.Impact.BaseMetricV3.CVSSv3.String(),
			Score:               i.Impact.BaseMetricV3.CVSSv3.Score,
			ExploitabilityScore: i.Impact.BaseMetricV3.ExploitabilityScore,
			ImpactScore:         i.Impact.BaseMetricV3.ImpactScore,
		},
	}

	return metadata
}

func (i *Item) Name() string {
	return i.CVE.CVEDataMeta.ID
}

func (n *CVSSv2) String() string {
	var str string
	addVec(&str, "AV", n.AccessVector)
	addVec(&str, "AC", n.AccessComplexity)
	addVec(&str, "Au", n.Authentication)
	addVec(&str, "C", n.ConfImpact)
	addVec(&str, "I", n.IntegImpact)
	addVec(&str, "A", n.AvailImpact)
	str = strings.TrimSuffix(str, "/")
	return str
}

func (n *CVSSv3) String() string {
	var str string
	addVec(&str, "AV", n.AttackVector)
	addVec(&str, "AC", n.AttackComplexity)
	addVec(&str, "PR", n.PrivilegesRequired)
	addVec(&str, "UI", n.UserInteraction)
	addVec(&str, "S", n.Scope)
	addVec(&str, "C", n.ConfImpact)
	addVec(&str, "I", n.IntegImpact)
	addVec(&str, "A", n.AvailImpact)
	str = strings.TrimSuffix(str, "/")

	if len(str) > 0 {
		return fmt.Sprintf("CVSS:3.0/%s", str)
	}
	return str
}

func addVec(str *string, vec, val string) {
	if val != "" {
		if let, ok := vectorValuesToLetters[val]; ok {
			*str = fmt.Sprintf("%s%s:%s/", *str, vec, let)
		} else {
			fmt.Println("ERROR: unknown value for CVSS VECTOR")
		}
	}
}

func (i *Item) Vulnerability() *database.Vulnerability {
	return &database.Vulnerability{
		Name:        i.Name(),
		Description: i.Summary(),
		Link:        fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", i.Name()),
		Metadata: map[string]interface{}{
			"NVD": i.Metadata(),
		},
	}
}

type constraintMatcher func(s string) bool

func exactMatch(s string) constraintMatcher {
	return func(v string) bool {
		return s == v
	}
}

func constraintWrapper(s string) constraintMatcher {
	cts, err := version.NewConstraint(s)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return func(_ string) bool {
			return false
		}
	}
	return func(v string) bool {
		ver, err := version.NewVersion(v)
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			return false
		}
		return cts.Check(ver)
	}
}

type intermediatePair struct {
	vendor, name, fixedVersion string
	constraint                 constraintMatcher
}

func allEmpty(strs ...string) bool {
	for _, s := range strs {
		if s != "" {
			return false
		}
	}
	return true
}

func recurseNode(node *Node) []*intermediatePair {
	var pairs []*intermediatePair
	for _, match := range node.CPEMatch {
		if match.Vulnerable {
			spl := strings.Split(match.CPE23URI, ":")
			if spl[2] != "a" {
				continue
			}
			var constraints []string
			var fixedVersion string
			if allEmpty(match.VersionStartIncluding, match.VersionEndExcluding, match.VersionEndIncluding) {
				pairs = append(pairs, &intermediatePair{vendor: spl[3], name: spl[4], constraint: exactMatch(spl[5])})
				continue
			}
			if match.VersionStartIncluding != "" {
				constraints = append(constraints, fmt.Sprintf(">=%s", match.VersionStartIncluding))
			}
			if match.VersionEndExcluding != "" {
				constraints = append(constraints, fmt.Sprintf("<%s", match.VersionEndExcluding))
				fixedVersion = match.VersionEndExcluding
			}
			if match.VersionEndIncluding != "" {
				constraints = append(constraints, fmt.Sprintf("<=%s", match.VersionEndIncluding))
			}
			wrapper := constraintWrapper(strings.Join(constraints, ","))
			pairs = append(pairs, &intermediatePair{vendor: spl[3], name: spl[4], fixedVersion: fixedVersion, constraint: wrapper})
		}
	}
	for _, c := range node.Children {
		pairs = append(pairs, recurseNode(c)...)
	}
	return pairs
}
