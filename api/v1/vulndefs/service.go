package vulndefs

import (
	"context"

	"github.com/gogo/protobuf/types"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	apiGRPC "github.com/stackrox/scanner/api/grpc"
	"github.com/stackrox/scanner/database"
	v1 "github.com/stackrox/scanner/generated/shared/api/v1"
	"github.com/stackrox/scanner/pkg/updater"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Service defines a vulnerability definitions service.
type Service interface {
	apiGRPC.APIService

	v1.VulnDefsServiceServer
}

// NewService returns the service for vulnerability definitions.
func NewService(db database.Datastore) Service {
	return &serviceImpl{
		db: db,
	}
}

type serviceImpl struct {
	db database.Datastore
}

// RegisterServiceServer registers this service with the given gRPC Server.
func (s *serviceImpl) RegisterServiceServer(server *grpc.Server) {
	v1.RegisterVulnDefsServiceServer(server, s)
}

// RegisterServiceHandler registers this service with the given gRPC Gateway endpoint.
func (s *serviceImpl) RegisterServiceHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return v1.RegisterVulnDefsServiceHandler(ctx, mux, conn)
}

func (s *serviceImpl) GetVulnDefsMetadata(context.Context, *v1.Empty) (*v1.VulnDefsMetadata, error) {
	t, err := updater.GetLastUpdatedTime(s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to obtain vulnerability definitions update timestamp: %v", err)
	}

	ts, err := types.TimestampProto(t)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to obtain vulnerability definitions update timestamp: %v", err)
	}

	return &v1.VulnDefsMetadata{
		LastUpdatedTime: ts,
	}, nil
}
