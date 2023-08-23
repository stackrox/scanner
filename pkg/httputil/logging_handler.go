package httputil

import (
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/httputil"
)

// Protocol represents a networking protocol.
type Protocol string

const (
	// HTTP represents HTTP as a protocol.
	HTTP Protocol = "HTTP"
	// GRPC represents gRPC as a protocol.
	GRPC Protocol = "gRPC"
)

// WithLogging wraps the http.Handler with basic logging.
func WithLogging(h http.Handler, protocol Protocol) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logrus.WithFields(map[string]interface{}{
			"Method": r.Method,
			"URI":    r.URL.String(),
		}).Infof("Received %s request from %s", protocol, r.RemoteAddr)

		stw := httputil.NewStatusTrackingWriter(w)

		start := time.Now()
		h.ServeHTTP(stw, r)
		duration := time.Since(start).String()

		var statusCode int
		if code := stw.GetStatusCode(); code != nil {
			statusCode = *code
		}

		logrus.WithFields(map[string]interface{}{
			"Method":   r.Method,
			"URI":      r.URL.String(),
			"Duration": duration,
			"Status":   statusCode,
		}).Infof("Finished %s request from %s", protocol, r.RemoteAddr)
	})
}
