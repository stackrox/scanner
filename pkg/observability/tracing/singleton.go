package tracing

import (
	"github.com/stackrox/rox/pkg/sync"
)

var (
	once    sync.Once
	handler TracerHandler
)

func initialize() {
	handler = NewHandler()
}

// Singleton returns the tracer handler instance.
func Singleton() TracerHandler {
	once.Do(initialize)
	return handler
}
