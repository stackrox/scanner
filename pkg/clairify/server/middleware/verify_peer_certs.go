// Any changes to this file should be considered for its counterpart:
// api/grpc/verify_peer_certs_interceptor.go

package middleware

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/stackrox/rox/pkg/httputil"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/pkg/env"
	"github.com/stackrox/scanner/pkg/mtls"
	"google.golang.org/grpc/codes"
)

var (
	verifyPeerCertsAllowList = set.NewFrozenStringSet(
		"/clairify/ping",
		"/scanner/ping",
	)
)

// VerifyPeerCerts returns http middleware to verify peer certs for certain endpoints.
func VerifyPeerCerts() mux.MiddlewareFunc {
	skipPeerValidation := env.SkipPeerValidation.Enabled()

	verifyPeerCertificate := mtls.VerifyCentralPeerCertificate
	if env.LocalScanning.Enabled() {
		verifyPeerCertificate = mtls.VerifyCentralAndSensorPeerCertificates
	} else if env.SlimMode.Enabled() {
		verifyPeerCertificate = mtls.VerifySensorPeerCertificate
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !skipPeerValidation && !verifyPeerCertsAllowList.Contains(r.RequestURI) {
				if err := verifyPeerCertificate(r.TLS); err != nil {
					httputil.WriteGRPCStyleError(w, codes.InvalidArgument, err)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
