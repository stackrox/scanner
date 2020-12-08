package mtls

import (
	"crypto/x509"

	"github.com/pkg/errors"
)

const (
	centralCN = "CENTRAL_SERVICE: Central"
)

// VerifyCentralCertificate verifies one of the peer certificates contains the central.stackrox hostname
// The CA should have already been verified via tls.VerifyClientCertIfGiven
func VerifyCentralCertificate(peerCerts []*x509.Certificate) error {
	if len(peerCerts) == 0 {
		return errors.New("no peer certificates found")
	}
	if peerCN := peerCerts[0].Subject.CommonName; peerCN != centralCN {
		return errors.Errorf("peer certificate common name %q does not match expected common name: %s", peerCN, centralCN)
	}
	return nil
}
