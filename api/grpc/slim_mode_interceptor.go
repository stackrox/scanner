package grpc

import (
	"context"
	"github.com/sirupsen/logrus"

	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/pkg/env"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// Method name(s) taken from the respective generated pb.go file(s).
	slimModeMethodsAllowlist = set.NewFrozenStringSet(
		"/scannerV1.PingService/Ping",
		"/scannerV1.ImageScanService/GetImageComponents",
	)
)

func slimModeUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	slimMode := env.SlimMode.Enabled()

	logrus.WithFields(map[string]interface{}{
		"Slim Mode": env.SlimMode.Enabled(),
	}).Error("SCANNER IS HERE TOO YAYAYAY")

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if slimMode && !slimModeMethodsAllowlist.Contains(info.FullMethod) {
			return nil, status.Error(codes.NotFound, "request not available in slim-mode")
		}

		return handler(ctx, req)
	}
}
