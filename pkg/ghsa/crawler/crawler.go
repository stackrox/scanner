package crawler

import (
	"context"

	"github.com/machinebox/graphql"
	"github.com/stackrox/scanner/pkg/ghsa"
)

const (
	apiEndpoint = `https://api.github.com/graphql`
	query       = `
query($start: String) {
  securityVulnerabilities(orderBy: {field:UPDATED_AT, direction:DESC}, ecosystem:GO, first: 100, after: $start) {
    nodes {
      package {
        name
      }
      severity
      updatedAt
      advisory {
        ghsaId
        summary
        description
        identifiers {
          type
          value
        }
        origin
        permalink

        references {
          url
        }
        publishedAt
        updatedAt
        withdrawnAt

      }
      firstPatchedVersion {
        identifier
      }
      vulnerableVersionRange
    }
    pageInfo {
      endCursor
      hasNextPage
    }
  }
}
`
)

// Crawler allows crawling the GHSA database
type Crawler interface {
	FetchAll(ctx context.Context) ([]*ghsa.SecurityVulnerabilityConnection, error)
}

// NewCrawler creates a new crawler with the given API token.
func NewCrawler(token string) Crawler {
	return &crawler{
		client: graphql.NewClient(apiEndpoint),
		token:  token,
	}
}

type crawler struct {
	client *graphql.Client
	token  string
}

func (c *crawler) FetchAll(ctx context.Context) ([]*ghsa.SecurityVulnerabilityConnection, error) {
	req := graphql.NewRequest(query)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Var("start", nil)

	var result []*ghsa.SecurityVulnerabilityConnection
	for {
		var resp queryResponse
		if err := c.client.Run(ctx, req, &resp); err != nil {
			return nil, err
		}
		result = append(result, resp.SecurityVulnerabilities.Nodes...)
		if !resp.SecurityVulnerabilities.PageInfo.HasNextPage {
			break
		}
		req.Var("start", resp.SecurityVulnerabilities.PageInfo.EndCursor)
	}

	return result, nil
}
