package nvdloader

import (
	"github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
)

// EnrichCVEItem enriches a single CVE feed item
func EnrichCVEItem(item *schema.NVDCVEFeedJSON10DefCVEItem, enrichmentMap map[string][]*FileFormatWrapper) {
	lastModified := item.LastModifiedDate
	for _, enrichedEntry := range enrichmentMap[item.CVE.CVEDataMeta.ID] {
		// Add the CPE matches instead of removing for backwards compatibility purposes
		item.Configurations.Nodes = append(item.Configurations.Nodes, &schema.NVDCVEFeedJSON10DefNode{
			CPEMatch: enrichedEntry.AffectedPackages,
			Operator: "OR",
		})
		if enrichedEntry.LastUpdated > lastModified {
			lastModified = enrichedEntry.LastUpdated
		}
	}
	if lastModified != "" {
		item.LastModifiedDate = lastModified
	}
}
