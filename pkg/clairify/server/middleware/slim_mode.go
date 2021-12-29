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
	errSlimMode = errors.New("request not available in slim-mode")

	slimModeAllowList = set.NewFrozenStringSet(
		"/clairify/ping",
		"/scanner/ping",
	)
)

// SlimMode returns middleware which only allows the request to continue when NOT in slim-mode.
func SlimMode() mux.MiddlewareFunc {
	slimMode := env.SlimMode.Enabled()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if slimMode && !slimModeAllowList.Contains(r.RequestURI) {
				httputil.WriteGRPCStyleError(w, codes.NotFound, errSlimMode)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
