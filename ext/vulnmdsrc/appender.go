package vulnmdsrc

import (
	"strings"

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/vulnmdsrc/nvd"
	"github.com/stackrox/scanner/ext/vulnmdsrc/redhat"
)

// Appenders returns a slice of each Appender singleton.
func Appenders() []Appender {
	return []Appender{
		nvd.SingletonAppender(),
		redhat.SingletonAppender(),
	}
}

// SingletonAppender returns the appropriate Appender singleton based on the given vulnerability.
func SingletonAppender(vuln *database.Vulnerability) Appender {
	if strings.HasPrefix(vuln.Namespace.Name, "centos") {
		return redhat.SingletonAppender()
	}

	return nvd.SingletonAppender()
}

