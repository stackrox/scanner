package crawler

import "github.com/stackrox/scanner/pkg/ghsa"

type pageInfo struct {
	EndCursor   string `json:"endCursor,omitempty"`
	HasNextPage bool   `json:"hasNextPage,omitempty"`
}

type securityVulnerabilitiesResponse struct {
	Nodes    []*ghsa.SecurityVulnerabilityConnection `json:"nodes,omitempty"`
	PageInfo pageInfo
}

type queryResponse struct {
	SecurityVulnerabilities securityVulnerabilitiesResponse `json:"securityVulnerabilities,omitempty"`
}
