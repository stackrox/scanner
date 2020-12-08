package mtls

import (
	"net/http"

	"github.com/pkg/errors"
)

const (
	centralCN = "CENTRAL_SERVICE: Central"
)

// VerifyCentralPeerCertificate verifies that the peer certificate has the Central Common Name
// The CA should have already been verified via tls.VerifyClientCertIfGiven
func VerifyCentralPeerCertificate(r *http.Request) error {
	if r.TLS == nil {
		return errors.New("no tls connection state")
	}
	peerCerts := r.TLS.PeerCertificates
	if len(peerCerts) == 0 {
		return errors.New("no peer certificates found")
	}
	if peerCN := peerCerts[0].Subject.CommonName; peerCN != centralCN {
		return errors.Errorf("peer certificate common name %q does not match expected common name: %s", peerCN, centralCN)
	}
	return nil
}
