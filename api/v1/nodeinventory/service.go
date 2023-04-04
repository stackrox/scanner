package nodeinventory

import (
	"context"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	apiGRPC "github.com/stackrox/scanner/api/grpc"
	v1 "github.com/stackrox/scanner/generated/scanner/api/v1"
	"github.com/stackrox/scanner/pkg/analyzer/detection"
	"github.com/stackrox/scanner/pkg/env"
	"github.com/stackrox/scanner/pkg/nodeinventory"
	"google.golang.org/grpc"
)

// Service defines the node scanning service.
type Service interface {
	apiGRPC.APIService

	v1.NodeInventoryServiceServer
}

// NewService returns the service for node scanning
func NewService(nodeName string) Service {
	cachedCollector := nodeinventory.NewCachingScanner(
		&nodeinventory.Scanner{},
		"/cache/inventory-cache",
		env.NodeScanningCacheDuration.DurationSetting(),
		env.NodeScanningInitialBackoff.DurationSetting(),
		env.NodeScanningMaxBackoff.DurationSetting(),
		func(duration time.Duration) { time.Sleep(duration) })

	return &serviceImpl{
		inventoryCollector: cachedCollector,
		nodeName:           nodeName,
	}
}

type serviceImpl struct {
	inventoryCollector nodeinventory.NodeInventorizer
	nodeName           string
}

func (s *serviceImpl) GetNodeInventory(_ context.Context, _ *v1.GetNodeInventoryRequest) (*v1.GetNodeInventoryResponse, error) {
	inventoryScan, err := s.inventoryCollector.Scan(s.nodeName)
	if err != nil {
		log.Errorf("error analyzing node %q: %v", s.nodeName, err)
		switch {
		case errors.Is(err, detection.ErrNodeScanningUnavailable):
			return nil, err
		default:
			return nil, errors.New("Internal scanner error: failed to scan node")
		}
	}

	log.Infof("Finished node scan: %s", inventoryScan.StringSummary())

	return &v1.GetNodeInventoryResponse{
		NodeName:   s.nodeName,
		Components: inventoryScan.Components,
		Notes:      inventoryScan.Notes,
	}, nil
}

// RegisterServiceServer registers this service with the given gRPC Server.
func (s *serviceImpl) RegisterServiceServer(grpcServer *grpc.Server) {
	v1.RegisterNodeInventoryServiceServer(grpcServer, s)
}

// RegisterServiceHandler registers this service with the given gRPC Gateway endpoint.
func (s *serviceImpl) RegisterServiceHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return v1.RegisterNodeInventoryServiceHandler(ctx, mux, conn)
}
