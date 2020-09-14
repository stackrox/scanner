package vulnmdsrc

import (
	"strings"

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/vulnmdsrc/nvd"
	"github.com/stackrox/scanner/ext/vulnmdsrc/redhat"
	"github.com/stackrox/scanner/ext/vulnmdsrc/types"
)

// Appenders returns a slice of each Appender singleton.
func Appenders() []types.Appender {
	return []types.Appender{
		nvd.SingletonAppender(),
		redhat.SingletonAppender(),
	}
}

// AppenderForVuln returns the appropriate Appender based on the given vulnerability.
func AppenderForVuln(vuln *database.Vulnerability) types.Appender {
	if strings.HasPrefix(vuln.Namespace.Name, "centos") {
		return redhat.SingletonAppender()
	}

	return nvd.SingletonAppender()
}
