// Package mtls contains a copy of the subset of pkg/mtls in the rox repo that is required.
// The code is copied, rather than submodule rox, for simplicity, and because we hope this
// code won't change too much.
// If you see something wrong with any of the code below, and need to change it, please take care to
// keep it in sync with the rox code.
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"sync"

	"github.com/pkg/errors"
)

const (
	certsPrefix = "/run/secrets/stackrox.io/certs/"

	// caCertFilePath is where the certificate is stored.
	caCertFilePath = certsPrefix + "ca.pem"

	// CertFilePath is where the certificate is stored.
	certFilePath = certsPrefix + "cert.pem"
	// KeyFilePath is where the key is stored.
	keyFilePath = certsPrefix + "key.pem"

	centralHostname = "central.stackrox"
)

var (
	readCAOnce sync.Once
	caCert     *x509.Certificate
	caCertDER  []byte
	caCertErr  error
)

// leafCertificateFromFile reads a tls.Certificate (including private key and cert)
// from the canonical locations on non-central services.
func leafCertificateFromFile() (tls.Certificate, error) {
	return tls.LoadX509KeyPair(certFilePath, keyFilePath)
}

// TLSServerConfig returns a TLS config for a server that is in the Rox mTLS system.
func TLSServerConfig() (*tls.Config, error) {
	serverTLSCert, err := leafCertificateFromFile()
	if err != nil {
		return nil, errors.Wrap(err, "tls conversion")
	}

	conf, err := config(serverTLSCert)
	if err != nil {
		return nil, err
	}
	conf.ClientAuth = tls.VerifyClientCertIfGiven
	conf.NextProtos = []string{"h2"}
	return conf, nil
}

// defaultTLSServerConfig returns the default TLS config for servers in StackRox
func defaultTLSServerConfig(certPool *x509.CertPool, certs []tls.Certificate) *tls.Config {
	// Government clients require TLS >=1.2 and require that AES-256 be preferred over AES-128
	return &tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    certPool,
		Certificates: certs,
	}
}

// loadCACertDER reads the PEM-decoded bytes of the cert from the local file system.
func loadCACertDER() ([]byte, error) {
	b, err := ioutil.ReadFile(caCertFilePath)
	if err != nil {
		return nil, errors.Wrap(err, "file access")
	}
	decoded, _ := pem.Decode(b)
	if decoded == nil {
		return nil, errors.New("invalid PEM")
	}
	return decoded.Bytes, nil
}

// readCACert reads the cert from the local file system and returns the cert and the DER encoding.
func readCACert() (*x509.Certificate, []byte, error) {
	readCAOnce.Do(func() {
		der, err := loadCACertDER()
		if err != nil {
			caCertErr = errors.Wrap(err, "CA cert could not be decoded")
			return
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			caCertErr = errors.Wrap(err, "CA cert could not be parsed")
			return
		}
		caCert = cert
		caCertDER = der
	})
	return caCert, caCertDER, caCertErr
}

// trustedCertPool creates a CertPool that contains the CA certificate.
func trustedCertPool() (*x509.CertPool, error) {
	caCert, _, err := readCACert()
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)
	return certPool, nil
}

func config(serverBundle tls.Certificate) (*tls.Config, error) {
	certPool, err := trustedCertPool()
	if err != nil {
		return nil, errors.Wrap(err, "CA cert")
	}

	// This is based on TLSClientAuthServerConfig from cfssl/transport.
	// However, we don't use enough of their ecosystem to fully use it yet.
	cfg := defaultTLSServerConfig(certPool, []tls.Certificate{serverBundle})
	return cfg, nil
}

// TLSClientConfigForCentral returns a TLS client config that can be used to talk to Central.
func TLSClientConfigForCentral() (*tls.Config, error) {
	certPool, err := trustedCertPool()
	if err != nil {
		return nil, errors.Wrap(err, "loading trusted cert pool")
	}
	leafCert, err := leafCertificateFromFile()
	if err != nil {
		return nil, errors.Wrap(err, "loading leaf cert")
	}
	conf := &tls.Config{
		ServerName: centralHostname,
		Certificates: []tls.Certificate{
			leafCert,
		},
		RootCAs: certPool,
	}
	return conf, nil
}
