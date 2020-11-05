package cache

import (
	"os"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/utils"
)

var (
	once     sync.Once
	instance Cache
)

// Singleton returns the cache instance to use.
func Singleton() Cache {
	once.Do(func() {
		instance = New()

		if definitionsDir := os.Getenv("K8S_DEFINITIONS_DIR"); definitionsDir != "" {
			log.Info("Loading Kubernetes definitions into cache")
			utils.Must(instance.LoadFromDirectory(definitionsDir))
			log.Info("Done loading Kubernetes definitions into cache")
		}
	})
	return instance
}
