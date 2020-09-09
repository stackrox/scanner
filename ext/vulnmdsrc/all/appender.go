package all

import (
	"strings"

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/vulnmdsrc"
	"github.com/stackrox/scanner/ext/vulnmdsrc/nvd"
	"github.com/stackrox/scanner/ext/vulnmdsrc/redhat"
)

// Appenders returns a slice of each Appender singleton.
func Appenders() []vulnmdsrc.Appender {
	return []vulnmdsrc.Appender{
		nvd.SingletonAppender(),
		redhat.SingletonAppender(),
	}
}

// AppenderForVuln returns the appropriate Appender based on the given vulnerability.
func AppenderForVuln(vuln *database.Vulnerability) vulnmdsrc.Appender {
	if strings.HasPrefix(vuln.Namespace.Name, "centos") {
		return redhat.SingletonAppender()
	}

	return nvd.SingletonAppender()
}
