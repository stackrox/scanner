package middleware

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/httputil"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/pkg/env"
	"google.golang.org/grpc/codes"
)

var (
	errLiteMode = errors.New("request not available in lite-mode")

	liteModeAllowList = set.NewFrozenStringSet(
		"/clairify/ping",
		"/scanner/ping",
	)
)

// LiteMode returns middleware which only allows the request to continue when NOT in lite-mode.
func LiteMode() mux.MiddlewareFunc {
	liteMode := env.LiteMode.Enabled()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if liteMode && !liteModeAllowList.Contains(r.RequestURI) {
				httputil.WriteGRPCStyleError(w, codes.NotFound, errLiteMode)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
