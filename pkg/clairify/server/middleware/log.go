// Any changes to this file should be considered for its counterpart:
// api/grpc/logging_interceptor.go

package middleware

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

func Log() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logrus.WithFields(map[string]interface{}{
				"Method": r.Method,
				"URI":    r.URL.String(),
			}).Infof("Received HTTP request from %s", r.RemoteAddr)

			next.ServeHTTP(w, r)
		})
	}
}
