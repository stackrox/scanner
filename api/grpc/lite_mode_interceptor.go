package grpc

import (
	"context"

	"github.com/stackrox/rox/pkg/set"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// Method name(s) taken from the respective generated pb.go file(s).
	liteModeMethodsAllowlist = set.NewFrozenStringSet(
		"/scannerV1.ImageScanService/ImageScanAndGet",
		"/scannerV1.PingService/Ping",
	)
)

func liteModeUnaryServerInterceptor(liteMode bool) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if liteMode && !liteModeMethodsAllowlist.Contains(info.FullMethod) {
			// TODO: ensure this is the right status code.
			return nil, status.Error(codes.FailedPrecondition, "request not available in lite-mode")
		}

		return handler(ctx, req)
	}
}
