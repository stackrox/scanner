package licenses

import (
	"io/ioutil"

	log "github.com/sirupsen/logrus"
)

func fetchFromSecret(secretPath string) string {
	licenseKeyBytes, err := ioutil.ReadFile(secretPath)
	if err != nil {
		// Avoid logging the error so as to not leak the file name.
		log.Debug("no license found through secret")
		return ""
	}
	log.Debugf("Got license from secret.")
	return string(licenseKeyBytes)
}
