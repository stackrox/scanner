package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	centralTLSState = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{
				Subject: pkix.Name{
					CommonName: "CENTRAL_SERVICE: Central/serialNumber=02938402934802934702",
				},
			},
		},
	}

	sensorTLSState = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{
				Subject: pkix.Name{
					CommonName: "SENSOR_SERVICE: 00000000-0000-0000-0000-000000000000/serialNumber=02938402934802934702",
				},
			},
		},
	}
)

func TestVerifyCentralAndSensorPeerCertificates(t *testing.T) {
	assert.NoError(t, VerifyCentralAndSensorPeerCertificates(centralTLSState))
	assert.NoError(t, VerifyCentralAndSensorPeerCertificates(sensorTLSState))
}

func TestVerifyCentralPeerCertificate(t *testing.T) {
	assert.NoError(t, VerifyCentralPeerCertificate(centralTLSState))
	assert.Error(t, VerifyCentralPeerCertificate(sensorTLSState))
}

func TestVerifySensorPeerCertificate(t *testing.T) {
	assert.NoError(t, VerifySensorPeerCertificate(sensorTLSState))
	assert.Error(t, VerifySensorPeerCertificate(centralTLSState))
}
