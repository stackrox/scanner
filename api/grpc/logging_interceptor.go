package grpc

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

const pingMethod = `/scannerV1.PingService/Ping`

func loggingUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if info.FullMethod == pingMethod {
			// Don't bother logging pings.
			return handler(ctx, req)
		}

		logrus.WithFields(map[string]interface{}{
			"URI": info.FullMethod,
		}).Infof("Received gRPC request")

		start := time.Now()
		resp, err := handler(ctx, req)
		duration := fmt.Sprintf("%f seconds", time.Since(start).Seconds())

		logrus.WithFields(map[string]interface{}{
			"URI":      info.FullMethod,
			"Duration": duration,
		}).Infof("Finished gRPC request")

		return resp, err
	}
}
