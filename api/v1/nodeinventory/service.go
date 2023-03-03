package nodeinventory

import (
	"context"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	apiGRPC "github.com/stackrox/scanner/api/grpc"
	v1 "github.com/stackrox/scanner/generated/scanner/api/v1"
	"github.com/stackrox/scanner/pkg/nodeinventory"
	"google.golang.org/grpc"
)

// Service defines the node scanning service.
type Service interface {
	apiGRPC.APIService

	v1.NodeInventoryScanServiceServer
}

// NewService returns the service for node scanning
func NewService(nodeName string) Service {
	return &serviceImpl{
		inventoryCollector: &nodeinventory.Scanner{},
		nodeName:           nodeName,
	}
}

type serviceImpl struct {
	inventoryCollector *nodeinventory.Scanner
	nodeName           string
}

func (s *serviceImpl) GetNodeInventory(ctx context.Context, req *v1.GetNodeInventoryScanRequest) (*v1.GetNodeInventoryScanResponse, error) {
	inventoryScan, err := s.inventoryCollector.Scan(s.nodeName)
	if err != nil {
		log.Errorf("Error running inventoryCollector.Scan(%s): %v", s.nodeName, err)
		return nil, errors.New("Internal scanner error: failed to scan node")
	}

	log.Debugf("InventoryScan: %+v", inventoryScan)

	return &v1.GetNodeInventoryScanResponse{
		NodeName:   s.nodeName,
		Components: inventoryScan.Components,
		Notes:      inventoryScan.Notes,
	}, nil
}

// RegisterServiceServer registers this service with the given gRPC Server.
func (s *serviceImpl) RegisterServiceServer(grpcServer *grpc.Server) {
	v1.RegisterNodeInventoryScanServiceServer(grpcServer, s)
}

// RegisterServiceHandler registers this service with the given gRPC Gateway endpoint.
func (s *serviceImpl) RegisterServiceHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return v1.RegisterNodeInventoryScanServiceHandler(ctx, mux, conn)
}
