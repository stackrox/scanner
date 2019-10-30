package client

import (
	v1 "github.com/stackrox/scanner/generated/api/v1"
	"google.golang.org/grpc"
)

type Client struct {
	v1.ScanServiceClient
}

func NewClient(endpoint string) (*Client, error) {
	conn, err := grpc.Dial(endpoint, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	return &Client{
		ScanServiceClient: v1.NewScanServiceClient(conn),
	}, nil
}
