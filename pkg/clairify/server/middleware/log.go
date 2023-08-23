// Note: there is no gRPC equivalent to this, as this is, instead,
// captured upon calling ServeHTTP in api/grpc/grpc.go.

package middleware

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/stackrox/scanner/pkg/httputil"
)

// Log returns middleware which logs basic information about the incoming HTTP request.
func Log() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return httputil.WithLogging(next, httputil.HTTP)
	}
}
