// Any changes to this file should be considered for its counterpart:
// pkg/clairify/server/middleware/log.go

package grpc

import (
	"context"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func loggingUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		peerInfo, exists := peer.FromContext(ctx)
		if !exists {
			return nil, status.Error(codes.InvalidArgument, "unable to parse peer information from request context")
		}

		logrus.WithFields(map[string]interface{}{
			"Method": info.FullMethod,
		}).Infof("Received gRPC request from %v", peerInfo.Addr)

		return handler(ctx, req)
	}
}
