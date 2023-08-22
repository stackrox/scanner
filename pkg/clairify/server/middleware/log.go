// Any changes to this file should be considered for its counterpart:
// api/grpc/logging_interceptor.go

package middleware

import (
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// Log returns middleware which logs basic information about the incoming HTTP request.
func Log() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logrus.WithFields(map[string]interface{}{
				"Method": r.Method,
				"URI":    r.URL.String(),
			}).Infof("Received HTTP request from %s", r.RemoteAddr)

			start := time.Now()

			rw := newResponseWriter(w)
			next.ServeHTTP(rw, r)

			logrus.WithFields(map[string]interface{}{
				"Method":   r.Method,
				"URI":      r.URL.String(),
				"Duration": time.Since(start).String(),
				"Status":   rw.statusCode,
			}).Infof("Finished HTTP request from %s", r.RemoteAddr)
		})
	}
}

var _ http.ResponseWriter = (*responseWriter)(nil)

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		statusCode:     -1,
	}
}

func (s *responseWriter) Write(b []byte) (int, error) {
	n, err := s.ResponseWriter.Write(b)

	// From the docs:
	//
	// If WriteHeader is not called explicitly, the first call to Write
	// will trigger an implicit WriteHeader(http.StatusOK).
	// Thus explicit calls to WriteHeader are mainly used to
	// send error codes or 1xx informational responses.
	//
	// So, if s.statusCode is not set by this point, then the status code
	// is http.StatusOK, 200.
	if s.statusCode == -1 {
		s.statusCode = http.StatusOK
	}

	return n, err
}

func (s *responseWriter) WriteHeader(statusCode int) {
	s.ResponseWriter.WriteHeader(statusCode)
	s.statusCode = statusCode
}
