// Any changes to this file should be considered for its counterpart:
// pkg/clairify/server/middleware/log.go

package grpc

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func loggingUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		addr := "unknown"

		addrs := metadata.ValueFromIncomingContext(ctx, "x-forwarded-for")
		if len(addrs) > 0 {
			addr = addrs[0]
		}

		md, _ := metadata.FromIncomingContext(ctx)
		logrus.WithFields(map[string]interface{}{
			"Method": info.FullMethod,
			"HEADERS": md,
		}).Infof("Received gRPC request from %s", addr)

		start := time.Now()

		resp, err := handler(ctx, req)

		logrus.WithFields(map[string]interface{}{
			"Method":   info.FullMethod,
			"Duration": time.Since(start).String(),
		}).Infof("Finished gRPC request from %s", addr)

		return resp, err
	}
}
