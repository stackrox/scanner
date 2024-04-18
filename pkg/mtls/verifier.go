package mtls

import (
	"crypto/tls"
	"strings"

	"github.com/pkg/errors"
	"github.com/stackrox/scanner/pkg/env"
)

const (
	centralCN = "CENTRAL_SERVICE: "
	sensorCN  = "SENSOR_SERVICE: "
)

// VerifyPeerCertificate verifies the given peer certificate.
// By default, it verifies the certificate has the Central or Sensor Common Name.
// If ROX_SLIM_MODE is enabled, then is verifies it has the Sensor Common Name.
// The CA should have already been verified via tls.VerifyClientCertIfGiven.
func VerifyPeerCertificate(tls *tls.ConnectionState) error {
	verifyPeerCertificate := verifyCentralOrSensorPeerCertificate
	if env.SlimMode.Enabled() {
		verifyPeerCertificate = verifySensorPeerCertificate
	}

	return verifyPeerCertificate(tls)
}

// verifyCentralOrSensorPeerCertificate verifies that the peer certificate has
// either the Central Common Name or the Sensor Common Name.
// The CA should have already been verified via tls.VerifyClientCertIfGiven.
func verifyCentralOrSensorPeerCertificate(tls *tls.ConnectionState) error {
	return verifyPeerCertificate(tls, centralCN, sensorCN)
}

// verifyCentralPeerCertificate verifies that the peer certificate has the Central Common Name.
// The CA should have already been verified via tls.VerifyClientCertIfGiven.
func verifyCentralPeerCertificate(tls *tls.ConnectionState) error {
	return verifyPeerCertificate(tls, centralCN)
}

// verifySensorPeerCertificate verifies that the peer certificate has the Sensor Common Name.
// The CA should have already been verified via tls.VerifyClientCertIfGiven.
func verifySensorPeerCertificate(tls *tls.ConnectionState) error {
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
