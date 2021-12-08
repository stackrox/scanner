package mtls

import (
	"crypto/tls"
	"strings"

	"github.com/pkg/errors"
)

const (
	centralCN = "CENTRAL_SERVICE: "
)

// VerifyCentralPeerCertificate verifies that the peer certificate has the Central Common Name
// The CA should have already been verified via tls.VerifyClientCertIfGiven
func VerifyCentralPeerCertificate(tls *tls.ConnectionState) error {
	if tls == nil {
		return errors.New("no tls connection state")
	}
	peerCerts := tls.PeerCertificates
	if len(peerCerts) == 0 {
		return errors.New("no peer certificates found")
	}
	if peerCN := peerCerts[0].Subject.CommonName; !strings.HasPrefix(peerCN, centralCN) {
		return errors.Errorf("peer certificate common name %q does not match expected common name prefix: %s", peerCN, centralCN)
	}
	return nil
}
