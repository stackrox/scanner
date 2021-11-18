package grpc

import (
	"context"

	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/pkg/env"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// Method name(s) taken from the respective generated pb.go file(s).
	verifyPeerCertsMethodsAllowList = set.NewFrozenStringSet(
		"/scannerV1.PingService/Ping",
	)
)

func verifyPeerCertsUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	skipPeerValidation := env.SkipPeerValidation.Enabled()

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if !skipPeerValidation && !verifyPeerCertsMethodsAllowList.Contains(info.FullMethod) {
			// TODO: ensure this is the right status code.
			return nil, status.Error(codes.FailedPrecondition, "request not available in lite-mode")
		}

		return handler(ctx, req)
	}
}
