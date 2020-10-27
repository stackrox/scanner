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

// AppendersForVuln returns the appropriate Appenders based on the given vulnerability.
func AppendersForVuln(vuln *database.Vulnerability) []types.Appender {
	if strings.HasPrefix(vuln.Namespace.Name, "centos") {
		return []types.Appender{
			redhat.SingletonAppender(),
			nvd.SingletonAppender(),
		}
	}

	return []types.Appender{nvd.SingletonAppender()}
}
