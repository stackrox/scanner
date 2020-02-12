package licenses

import (
	"io/ioutil"

	log "github.com/sirupsen/logrus"
)

func maybeFetchFromSecret() string {
	licenseKeyBytes, err := ioutil.ReadFile(secretLicensePath)
	if err != nil {
		// Avoid logging the error so as to not leak the file name.
		log.Debug("no license found through secret")
		return ""
	}
	log.Debug("Got license from secret.")
	return string(licenseKeyBytes)
}
