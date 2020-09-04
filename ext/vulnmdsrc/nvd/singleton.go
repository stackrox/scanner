package nvd

import (
	"github.com/stackrox/scanner/ext/vulnmdsrc"
)

var (
	nvdAppender = &appender{}
)

// SingletonAppender returns the instance of the NVD appender.
func SingletonAppender() vulnmdsrc.Appender {
	return nvdAppender
}
