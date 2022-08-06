package ping

import (
	"context"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	apiGRPC "github.com/stackrox/scanner/api/grpc"
	v1 "github.com/stackrox/scanner/generated/scanner/api/v1"
	"github.com/stackrox/scanner/pkg/version"
	"google.golang.org/grpc"
)

// Service defines the Ping service.
type Service interface {
	apiGRPC.APIService

	v1.PingServiceServer
}

// NewService returns a new Ping service.
func NewService() Service {
	return &serviceImpl{
		version: version.Version,
	}
}

type serviceImpl struct {
	v1.UnimplementedPingServiceServer

	version string
}

func (s *serviceImpl) Ping(context.Context, *v1.Empty) (*v1.PongMessage, error) {
	return &v1.PongMessage{
		ScannerVersion: s.version,
		Status:         "OK",
	}, nil
}

// RegisterServiceServer registers this service with the given gRPC Server.
func (s *serviceImpl) RegisterServiceServer(grpcServer *grpc.Server) {
	v1.RegisterPingServiceServer(grpcServer, s)
}

// RegisterServiceHandler registers this service with the given gRPC Gateway endpoint.
func (s *serviceImpl) RegisterServiceHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return v1.RegisterPingServiceHandler(ctx, mux, conn)
}
