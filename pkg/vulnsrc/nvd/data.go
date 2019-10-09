package nvd

import (
	"encoding/json"
	"io/ioutil"
	"strings"
)

type CVEDataMeta struct {
	ID string
}

type CVE struct {
	CVEDataMeta *CVEDataMeta `json:"CVE_data_meta"`
}

type Match struct {
	Vulnerable bool `json:"vulnerable"`
	CPE23URI string `json:"cpe23Uri"`
}

type Node struct {
	CPEMatch []*Match `json:"cpe_match"`
}

type Configuration struct {
	Nodes []*Node `json:"nodes"`
}

type Item struct {
	CVE *CVE `json:"cve"`
	Configuration Configuration `json:"configurations"`
}

type NVDData struct {
	Items []*Item `json:"CVE_Items"`
}

func getCPEKeyFromURI(cpe string) (cpeKey, bool) {
	spl := strings.Split(cpe, ":")
	if len(spl) < 6 {
		return cpeKey{}, false
	}
	return cpeKey{vendor: spl[3], name: spl[4], version: spl[5]}, true
}

func GetCPEData(path string) (map[cpeKey]map[string]struct{}, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var data NVDData
	if err := json.Unmarshal(bytes, &data); err != nil {
		return nil, err
	}

	topLevelMap := make(map[cpeKey]map[string]struct{})
	for _, item := range data.Items {
		for _, node := range item.Configuration.Nodes {
			for _, matches := range node.CPEMatch {
				cpeKey, ok := getCPEKeyFromURI(matches.CPE23URI)
				if !ok {
					continue
				}
				vulnMap, ok := topLevelMap[cpeKey]
				if !ok {
					vulnMap = make(map[string]struct{})
					topLevelMap[cpeKey] = vulnMap
				}
				vulnMap[item.CVE.CVEDataMeta.ID] = struct{}{}
			}
		}
	}
	return topLevelMap, nil
}
