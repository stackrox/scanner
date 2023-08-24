package grpc

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

func loggingUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
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
