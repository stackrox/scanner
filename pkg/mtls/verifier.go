package mtls

import (
	"crypto/x509"
	"strings"

	"github.com/pkg/errors"
)

// VerifyCentralCertificate verifies one of the peer certificates contains the central.stackrox hostname
// The CA should have already been verified via tls.VerifyClientCertIfGiven
func VerifyCentralCertificate(peerCerts []*x509.Certificate) error {
	if len(peerCerts) == 0 {
		return errors.New("no peer certificates found")
	}
	var invalidDNSNames []string
	for _, peer := range peerCerts {
		for _, dnsName := range peer.DNSNames {
			if dnsName == centralHostname {
				return nil
			}
			invalidDNSNames = append(invalidDNSNames, dnsName)
		}
	}
	return errors.Errorf("did not find %v in DNS Names from peer certificates: %s", centralHostname, strings.Join(invalidDNSNames, ", "))
}
