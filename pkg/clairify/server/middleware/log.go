// Note: there is no gRPC equivalent to this, as this is, instead,
// captured upon calling ServeHTTP in api/grpc/grpc.go.

package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/httputil"
)

// Log returns middleware which logs basic information about the incoming HTTP request.
func Log() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logrus.WithFields(map[string]interface{}{
				"Method": r.Method,
				"URI":    r.URL.String(),
			}).Infof("Received HTTP request from %s", r.RemoteAddr)

			stw := httputil.NewStatusTrackingWriter(w)

			start := time.Now()
			next.ServeHTTP(stw, r)
			duration := fmt.Sprintf("%f seconds", time.Since(start).Seconds())

			var statusCode int
			if code := stw.GetStatusCode(); code != nil {
				statusCode = *code
			}

			logrus.WithFields(map[string]interface{}{
				"Method":   r.Method,
				"URI":      r.URL.String(),
				"Duration": duration,
				"Status":   statusCode,
			}).Infof("Finished HTTP request from %s", r.RemoteAddr)
		})
	}
}
