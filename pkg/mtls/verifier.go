package mtls

import (
	"net/http"
	"strings"

	"github.com/pkg/errors"
)

const (
	centralOU = "CENTRAL_SERVICE"
)

// VerifyCentralPeerCertificate verifies that the peer certificate has the Central Organizational Unit
// The CA should have already been verified via tls.VerifyClientCertIfGiven
func VerifyCentralPeerCertificate(r *http.Request) error {
	if r.TLS == nil {
		return errors.New("no tls connection state")
	}
	peerCerts := r.TLS.PeerCertificates
	if len(peerCerts) == 0 {
		return errors.New("no peer certificates found")
	}
	organizationalUnits := peerCerts[0].Subject.OrganizationalUnit
	if len(organizationalUnits) == 0 {
		return errors.New("peer certificate does not contain an OU")
	}

	for _, ou := range organizationalUnits {
		if strings.EqualFold(ou, centralOU) {
			return nil
		}
	}
	return errors.Errorf("peer certificate OUs %+v does not match expected OU: %s", organizationalUnits, centralOU)
}
