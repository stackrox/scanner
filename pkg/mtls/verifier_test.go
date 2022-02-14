package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifyCentralPeerCertificate(t *testing.T) {
	tlsState := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{
				Subject: pkix.Name{
					CommonName: "CENTRAL_SERVICE: Central/serialNumber=02938402934802934702",
				},
			},
		},
	}

	assert.NoError(t, VerifyCentralPeerCertificate(tlsState))
}

func TestVerifySensorPeerCertificate(t *testing.T) {
	tlsState := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{
				Subject: pkix.Name{
					CommonName: "SENSOR_SERVICE: 00000000-0000-0000-0000-000000000000/serialNumber=02938402934802934702",
				},
			},
		},
	}

	assert.NoError(t, VerifySensorPeerCertificate(tlsState))
}
