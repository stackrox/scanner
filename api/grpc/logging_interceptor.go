// Any changes to this file should be considered for its counterpart:
// pkg/clairify/server/middleware/log.go

package grpc

import (
	"context"
	"fmt"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

// loggingUnaryServerInterceptor adapts logrus logger to interceptor logger.
// This is a modified version of https://github.com/grpc-ecosystem/go-grpc-middleware/blob/v2.0.0/interceptors/logging/examples/logrus/example_test.go.
func loggingUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return logging.UnaryServerInterceptor(logging.LoggerFunc(func(_ context.Context, lvl logging.Level, msg string, fields ...any) {
		f := make(map[string]any, len(fields)/2)
		i := logging.Fields(fields).Iterator()
		if i.Next() {
			k, v := i.At()
			f[k] = v
		}

		switch lvl {
		case logging.LevelDebug:
			log.WithFields(f).Debug(msg)
		case logging.LevelInfo:
			log.WithFields(f).Info(msg)
		case logging.LevelWarn:
			log.WithFields(f).Warn(msg)
		case logging.LevelError:
			log.WithFields(f).Error(msg)
		default:
			panic(fmt.Sprintf("unknown level %v", lvl))
		}
	}))
}
