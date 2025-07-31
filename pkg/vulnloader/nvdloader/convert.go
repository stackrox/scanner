package nvdloader

import (
	"fmt"
	"strings"
	"time"

	apischema "github.com/facebookincubator/nvdtools/cveapi/nvd/schema"
	jsonschema "github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
)

const (
	apiTimeFormat  = "2006-01-02T15:04:05.999"
	jsonTimeFormat = "2006-01-02T15:04Z"
)

func toJSON10(vulns []*apischema.CVEAPIJSON20DefCVEItem) ([]*jsonschema.NVDCVEFeedJSON10DefCVEItem, error) {
	if vulns == nil {
		return nil, nil
	}

	cveItems := make([]*jsonschema.NVDCVEFeedJSON10DefCVEItem, 0, len(vulns))
	for _, vuln := range vulns {
		if vuln.CVE == nil {
			continue
		}

		// Ignore vulnerabilities older than 2002, as the JSON feeds only had >= 2002.
		parts := strings.Split(vuln.CVE.ID, "-")
		if len(parts) != 3 || parts[1] < "2002" {
			continue
		}

		cve := vuln.CVE

		modifiedTime, err := toTime(cve.LastModified)
		if err != nil {
			return nil, fmt.Errorf("converting LastModified for %s: %w", cve.ID, err)
		}
		publishedTime, err := toTime(cve.Published)
		if err != nil {
			return nil, fmt.Errorf("converting Published for %s: %w", cve.ID, err)
		}

		impact, err := toImpact(cve.Metrics)
		if err != nil {
			return nil, fmt.Errorf("converting Impact for %s: %w", cve.ID, err)
		}

		cveItems = append(cveItems, &jsonschema.NVDCVEFeedJSON10DefCVEItem{
			CVE:              toCVE(cve),
			Configurations:   toConfigurations(cve.Configurations),
			Impact:           impact,
			LastModifiedDate: modifiedTime,
			PublishedDate:    publishedTime,
		})
	}

	return cveItems, nil
}

// It is up to the caller to ensure cve is not nil.
func toCVE(cve *apischema.CVEAPIJSON20CVEItem) *jsonschema.CVEJSON40 {
	descriptions := make([]*jsonschema.CVEJSON40LangString, 0, 1)
	for _, description := range cve.Descriptions {
		// Only keep the English description.
		if description.Lang != "en" {
			continue
		}

		descriptions = append(descriptions, &jsonschema.CVEJSON40LangString{
			Lang:  description.Lang,
			Value: description.Value,
		})
	}

	return &jsonschema.CVEJSON40{
		CVEDataMeta: &jsonschema.CVEJSON40CVEDataMeta{
			ID: cve.ID,
		},
		Description: &jsonschema.CVEJSON40Description{
			DescriptionData: descriptions,
		},
	}
}

func toImpact(metrics *apischema.CVEAPIJSON20CVEItemMetrics) (*jsonschema.NVDCVEFeedJSON10DefImpact, error) {
	// Impact is allowed to be empty.
	if metrics == nil {
		return new(jsonschema.NVDCVEFeedJSON10DefImpact), nil
	}

	// It is possible and allowed for one or even both of these to be empty.
	metricV2 := toBaseMetricV2(metrics.CvssMetricV2)
	metricV3 := toBaseMetricV3(metrics.CvssMetricV30, metrics.CvssMetricV31)
	return &jsonschema.NVDCVEFeedJSON10DefImpact{
		BaseMetricV2: metricV2,
		BaseMetricV3: metricV3,
	}, nil
}

func toBaseMetricV2(metrics []*apischema.CVEAPIJSON20CVSSV2) *jsonschema.NVDCVEFeedJSON10DefImpactBaseMetricV2 {
	if len(metrics) == 0 {
		return nil
	}

	var cvss *apischema.CVEAPIJSON20CVSSV2
	var cvssData *apischema.CVSSV20
	for _, metric := range metrics {
		if metric.Type == "Primary" {
			cvss = metric
			cvssData = metric.CvssData
			break
		}
	}
	// 1.1 JSON feeds only serve the "Primary" (NVD) CVSS score.
	if cvss == nil {
		return nil
	}

	return &jsonschema.NVDCVEFeedJSON10DefImpactBaseMetricV2{
		AcInsufInfo: cvss.AcInsufInfo,
		CVSSV2: &jsonschema.CVSSV20{
			AccessComplexity:           cvssData.AccessComplexity,
			AccessVector:               cvssData.AccessVector,
			Authentication:             cvssData.Authentication,
			AvailabilityImpact:         cvssData.AvailabilityImpact,
			AvailabilityRequirement:    cvssData.AvailabilityRequirement,
			BaseScore:                  cvssData.BaseScore,
			CollateralDamagePotential:  cvssData.CollateralDamagePotential,
			ConfidentialityImpact:      cvssData.ConfidentialityImpact,
			ConfidentialityRequirement: cvssData.ConfidentialityRequirement,
			EnvironmentalScore:         cvssData.EnvironmentalScore,
			Exploitability:             cvssData.Exploitability,
			IntegrityImpact:            cvssData.IntegrityImpact,
			IntegrityRequirement:       cvssData.IntegrityRequirement,
			RemediationLevel:           cvssData.RemediationLevel,
			ReportConfidence:           cvssData.ReportConfidence,
			TargetDistribution:         cvssData.TargetDistribution,
			TemporalScore:              cvssData.TemporalScore,
			VectorString:               cvssData.VectorString,
			Version:                    cvssData.Version,
		},
		ExploitabilityScore:     cvss.ExploitabilityScore,
		ImpactScore:             cvss.ImpactScore,
		ObtainAllPrivilege:      cvss.ObtainAllPrivilege,
		ObtainOtherPrivilege:    cvss.ObtainOtherPrivilege,
		ObtainUserPrivilege:     cvss.ObtainUserPrivilege,
		Severity:                cvss.BaseSeverity,
		UserInteractionRequired: cvss.UserInteractionRequired,
	}
}

func toBaseMetricV3(metrics30 []*apischema.CVEAPIJSON20CVSSV30, metrics31 []*apischema.CVEAPIJSON20CVSSV31) *jsonschema.NVDCVEFeedJSON10DefImpactBaseMetricV3 {
	// Prefer CVSS 3.1.
	baseMetric := toBaseMetricV31(metrics31)
	if baseMetric != nil {
		return baseMetric
	}

	baseMetric = toBaseMetricV30(metrics30)
	if baseMetric != nil {
		return baseMetric
	}

	return nil
}

func toBaseMetricV31(metrics []*apischema.CVEAPIJSON20CVSSV31) *jsonschema.NVDCVEFeedJSON10DefImpactBaseMetricV3 {
	var cvss *apischema.CVEAPIJSON20CVSSV31
	var cvssData *apischema.CVSSV31
	for _, metric := range metrics {
		if metric.Type == "Primary" {
			cvss = metric
			cvssData = metric.CvssData
			break
		}
	}
	// 1.1 JSON feeds only serve the "Primary" (NVD) CVSS score.
	if cvss == nil {
		return nil
	}

	return &jsonschema.NVDCVEFeedJSON10DefImpactBaseMetricV3{
		CVSSV3: &jsonschema.CVSSV30{
			AttackComplexity:              cvssData.AttackComplexity,
			AttackVector:                  cvssData.AttackVector,
			AvailabilityImpact:            cvssData.AvailabilityImpact,
			AvailabilityRequirement:       cvssData.AvailabilityRequirement,
			BaseScore:                     cvssData.BaseScore,
			BaseSeverity:                  cvssData.BaseSeverity,
			ConfidentialityImpact:         cvssData.ConfidentialityImpact,
			ConfidentialityRequirement:    cvssData.ConfidentialityRequirement,
			EnvironmentalScore:            cvssData.EnvironmentalScore,
			EnvironmentalSeverity:         cvssData.EnvironmentalSeverity,
			ExploitCodeMaturity:           cvssData.ExploitCodeMaturity,
			IntegrityImpact:               cvssData.IntegrityImpact,
			IntegrityRequirement:          cvssData.IntegrityRequirement,
			ModifiedAttackComplexity:      cvssData.ModifiedAttackComplexity,
			ModifiedAttackVector:          cvssData.ModifiedAttackVector,
			ModifiedAvailabilityImpact:    cvssData.ModifiedAvailabilityImpact,
			ModifiedConfidentialityImpact: cvssData.ModifiedConfidentialityImpact,
			ModifiedIntegrityImpact:       cvssData.ModifiedIntegrityImpact,
			ModifiedPrivilegesRequired:    cvssData.ModifiedPrivilegesRequired,
			ModifiedScope:                 cvssData.ModifiedScope,
			ModifiedUserInteraction:       cvssData.ModifiedUserInteraction,
			PrivilegesRequired:            cvssData.PrivilegesRequired,
			RemediationLevel:              cvssData.RemediationLevel,
			ReportConfidence:              cvssData.ReportConfidence,
			Scope:                         cvssData.Scope,
			TemporalScore:                 cvssData.TemporalScore,
			TemporalSeverity:              cvssData.TemporalSeverity,
			UserInteraction:               cvssData.UserInteraction,
			VectorString:                  cvssData.VectorString,
			Version:                       cvssData.Version,
		},
		ExploitabilityScore: cvss.ExploitabilityScore,
		ImpactScore:         cvss.ImpactScore,
	}
}

func toBaseMetricV30(metrics []*apischema.CVEAPIJSON20CVSSV30) *jsonschema.NVDCVEFeedJSON10DefImpactBaseMetricV3 {
	var cvss *apischema.CVEAPIJSON20CVSSV30
	var cvssData *apischema.CVSSV30
	for _, metric := range metrics {
		if metric.Type == "Primary" {
			cvss = metric
			cvssData = metric.CvssData
			break
		}
	}
	// 1.1 JSON feeds only serve the "Primary" (NVD) CVSS score.
	if cvss == nil {
		return nil
	}

	return &jsonschema.NVDCVEFeedJSON10DefImpactBaseMetricV3{
		CVSSV3: &jsonschema.CVSSV30{
			AttackComplexity:              cvssData.AttackComplexity,
			AttackVector:                  cvssData.AttackVector,
			AvailabilityImpact:            cvssData.AvailabilityImpact,
			AvailabilityRequirement:       cvssData.AvailabilityRequirement,
			BaseScore:                     cvssData.BaseScore,
			BaseSeverity:                  cvssData.BaseSeverity,
			ConfidentialityImpact:         cvssData.ConfidentialityImpact,
			ConfidentialityRequirement:    cvssData.ConfidentialityRequirement,
			EnvironmentalScore:            cvssData.EnvironmentalScore,
			EnvironmentalSeverity:         cvssData.EnvironmentalSeverity,
			ExploitCodeMaturity:           cvssData.ExploitCodeMaturity,
			IntegrityImpact:               cvssData.IntegrityImpact,
			IntegrityRequirement:          cvssData.IntegrityRequirement,
			ModifiedAttackComplexity:      cvssData.ModifiedAttackComplexity,
			ModifiedAttackVector:          cvssData.ModifiedAttackVector,
			ModifiedAvailabilityImpact:    cvssData.ModifiedAvailabilityImpact,
			ModifiedConfidentialityImpact: cvssData.ModifiedConfidentialityImpact,
			ModifiedIntegrityImpact:       cvssData.ModifiedIntegrityImpact,
			ModifiedPrivilegesRequired:    cvssData.ModifiedPrivilegesRequired,
			ModifiedScope:                 cvssData.ModifiedScope,
			ModifiedUserInteraction:       cvssData.ModifiedUserInteraction,
			PrivilegesRequired:            cvssData.PrivilegesRequired,
			RemediationLevel:              cvssData.RemediationLevel,
			ReportConfidence:              cvssData.ReportConfidence,
			Scope:                         cvssData.Scope,
			TemporalScore:                 cvssData.TemporalScore,
			TemporalSeverity:              cvssData.TemporalSeverity,
			UserInteraction:               cvssData.UserInteraction,
			VectorString:                  cvssData.VectorString,
			Version:                       cvssData.Version,
		},
		ExploitabilityScore: cvss.ExploitabilityScore,
		ImpactScore:         cvss.ImpactScore,
	}
}

func toConfigurations(configs []*apischema.CVEAPIJSON20Config) *jsonschema.NVDCVEFeedJSON10DefConfigurations {
	// Configurations is allowed to be empty.
	if len(configs) == 0 {
		return new(jsonschema.NVDCVEFeedJSON10DefConfigurations)
	}

	jsonConfigs := &jsonschema.NVDCVEFeedJSON10DefConfigurations{
		Nodes: make([]*jsonschema.NVDCVEFeedJSON10DefNode, 0, len(configs)),
	}
	for _, config := range configs {
		jsonConfigs.Nodes = append(jsonConfigs.Nodes, toNode(config))
	}

	return jsonConfigs
}

func toNode(config *apischema.CVEAPIJSON20Config) *jsonschema.NVDCVEFeedJSON10DefNode {
	// If there is only one node, then just create a single JSON node
	// using the API node's attributes.
	if len(config.Nodes) == 1 {
		node := config.Nodes[0]
		return &jsonschema.NVDCVEFeedJSON10DefNode{
			CPEMatch: toCPEMatch(node),
			Negate:   node.Negate,
			Operator: node.Operator,
		}
	}

	// The v2 API schema only makes it seem like there can be a single level of children.
	// I do not know if this holds true in practice in the 1.1 schema.
	// The samples I have checked seem to only have a single level of children,
	// and the fact the new schema only allows for a single level tells me
	// this is probably correct.
	children := make([]*jsonschema.NVDCVEFeedJSON10DefNode, 0, len(config.Nodes))
	for _, node := range config.Nodes {
		children = append(children, &jsonschema.NVDCVEFeedJSON10DefNode{
			CPEMatch: toCPEMatch(node),
			Negate:   node.Negate,
			Operator: node.Operator,
		})
	}

	return &jsonschema.NVDCVEFeedJSON10DefNode{
		Children: children,
		Negate:   config.Negate,
		Operator: config.Operator,
	}
}

func toCPEMatch(node *apischema.CVEAPIJSON20Node) []*jsonschema.NVDCVEFeedJSON10DefCPEMatch {
	cpeMatch := make([]*jsonschema.NVDCVEFeedJSON10DefCPEMatch, 0, len(node.CpeMatch))
	for _, cpe := range node.CpeMatch {
		jsonCPEMatch := &jsonschema.NVDCVEFeedJSON10DefCPEMatch{
			VersionEndExcluding:   cpe.VersionEndExcluding,
			VersionEndIncluding:   cpe.VersionEndIncluding,
			VersionStartExcluding: cpe.VersionStartExcluding,
			VersionStartIncluding: cpe.VersionStartIncluding,
			Vulnerable:            cpe.Vulnerable,
		}
		if strings.HasPrefix(cpe.Criteria, "cpe:2.3") {
			jsonCPEMatch.Cpe23Uri = cpe.Criteria
		} else {
			jsonCPEMatch.Cpe22Uri = cpe.Criteria
		}

		cpeMatch = append(cpeMatch, jsonCPEMatch)
	}

	return cpeMatch
}

func toTime(t string) (string, error) {
	apiTime, err := time.Parse(apiTimeFormat, t)
	if err != nil {
		return "", err
	}

	return apiTime.Format(jsonTimeFormat), nil
}
