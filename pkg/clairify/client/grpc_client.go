package client

import (
	"context"
	"github.com/pkg/errors"
	v1 "github.com/stackrox/scanner/generated/api/v1"
	"google.golang.org/grpc"
)

type ClairifyGRPC struct {
	client v1.ScanServiceClient
}

func NewGRPCClient(ctx context.Context, endpoint string) (*ClairifyGRPC, error) {
	cc, err := grpc.DialContext(ctx, endpoint)
	if err != nil {
		return nil, errors.Wrapf(err, "Unable to dial endpoint %s", endpoint)
	}
	return &ClairifyGRPC{
		client: v1.NewScanServiceClient(cc),
	}, nil
}

func (c *ClairifyGRPC) GetVulnerabilities() *v1.GetVulnerabilitiesResponse {
	c.client.GetVulnerabilities(context.Background(), )
}
