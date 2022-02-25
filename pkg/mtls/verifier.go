package mtls

import (
	"crypto/tls"
	"strings"

	"github.com/pkg/errors"
)

const (
	centralCN = "CENTRAL_SERVICE: "
	sensorCN  = "SENSOR_SERVICE: "
)

// VerifyCentralAndSensorPeerCertificates verifies that the peer certificate has
// either the Central Common Name or the Sensor Common Name.
// The CA should have already been verified via tls.VerifyClientCertIfGiven.
func VerifyCentralAndSensorPeerCertificates(tls *tls.ConnectionState) error {
	return verifyPeerCertificate(tls, centralCN, sensorCN)
}

// VerifyCentralPeerCertificate verifies that the peer certificate has the Central Common Name.
// The CA should have already been verified via tls.VerifyClientCertIfGiven.
func VerifyCentralPeerCertificate(tls *tls.ConnectionState) error {
	return verifyPeerCertificate(tls, centralCN)
}

// VerifySensorPeerCertificate verifies that the peer certificate has the Sensor Common Name.
// The CA should have already been verified via tls.VerifyClientCertIfGiven.
func VerifySensorPeerCertificate(tls *tls.ConnectionState) error {
	return verifyPeerCertificate(tls, sensorCN)
}

func verifyPeerCertificate(tls *tls.ConnectionState, expectedCNs ...string) error {
	if tls == nil {
		return errors.New("no tls connection state")
	}

	peerCerts := tls.PeerCertificates
	if len(peerCerts) == 0 {
		return errors.New("no peer certificates found")
	}

	peerCN := peerCerts[0].Subject.CommonName

	for _, expectedCN := range expectedCNs {
		if strings.HasPrefix(peerCN, expectedCN) {
			return nil
		}
	}

	return errors.Errorf("peer certificate common name %q does not match any expected common name prefix", peerCN)
}
