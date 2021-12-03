package grpc

import (
	"context"
	"github.com/stackrox/scanner/pkg/env"

	"github.com/stackrox/rox/pkg/set"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// Method name(s) taken from the respective generated pb.go file(s).
	liteModeMethodsAllowlist = set.NewFrozenStringSet(
		"/scannerV1.PingService/Ping",
	)
)

func liteModeUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	liteMode := env.LiteMode.Enabled()

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if liteMode && !liteModeMethodsAllowlist.Contains(info.FullMethod) {
			return nil, status.Error(codes.NotFound, "request not available in lite-mode")
		}

		return handler(ctx, req)
	}
}
