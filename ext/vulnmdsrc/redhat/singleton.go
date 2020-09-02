package redhat

import (
	"github.com/stackrox/scanner/ext/vulnmdsrc"
)

// SingletonAppender returns the instance of the Red Hat appender.
func SingletonAppender() vulnmdsrc.Appender {
	return &appender{}
}
