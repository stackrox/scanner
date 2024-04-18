package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/stackrox/scanner/pkg/env"
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

	fooTLSState = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{
				Subject: pkix.Name{
					CommonName: "FOO: RANDOM-STRING-HERE",
				},
			},
		},
	}
)

func TestVerifyPeerCertificate_Default(t *testing.T) {
	assert.NoError(t, VerifyPeerCertificate(centralTLSState))
	assert.NoError(t, VerifyPeerCertificate(sensorTLSState))
	assert.Error(t, VerifyPeerCertificate(fooTLSState))
}

func TestVerifyPeerCertificate_ROX_SLIM_MODE(t *testing.T) {
	t.Setenv(env.SlimMode.EnvVar(), "true")

	assert.Error(t, VerifyPeerCertificate(centralTLSState))
	assert.NoError(t, VerifyPeerCertificate(sensorTLSState))
	assert.Error(t, VerifyPeerCertificate(fooTLSState))
}

func TestVerifyCentralOrSensorPeerCertificate(t *testing.T) {
	assert.NoError(t, verifyCentralOrSensorPeerCertificate(centralTLSState))
	assert.NoError(t, verifyCentralOrSensorPeerCertificate(sensorTLSState))
	assert.Error(t, verifyCentralOrSensorPeerCertificate(fooTLSState))
}

func TestVerifyCentralPeerCertificate(t *testing.T) {
	assert.NoError(t, verifyCentralPeerCertificate(centralTLSState))
	assert.Error(t, verifyCentralPeerCertificate(sensorTLSState))
	assert.Error(t, verifyCentralPeerCertificate(fooTLSState))
}

func TestVerifySensorPeerCertificate(t *testing.T) {
	assert.Error(t, verifySensorPeerCertificate(centralTLSState))
	assert.NoError(t, verifySensorPeerCertificate(sensorTLSState))
	assert.Error(t, verifySensorPeerCertificate(fooTLSState))
}
