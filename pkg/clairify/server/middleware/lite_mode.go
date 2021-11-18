package middleware

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/httputil"
	"google.golang.org/grpc/codes"
)

var errLiteMode = errors.New("request not available in lite-mode")

// LiteMode returns middleware which only allows the request to continue when NOT in lite-mode.
func LiteMode(liteMode bool) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if liteMode {
				// TODO: see if this is the right code to use...
				httputil.WriteGRPCStyleError(w, codes.FailedPrecondition, errLiteMode)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
