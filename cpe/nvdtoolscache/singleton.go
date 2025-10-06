package nvdtoolscache

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
		var err error
		log.Info("TEMP: initializing nvdtooscache")
		instance, err = New()
		log.Info("TEMP: done initializing nvdtooscache")
		utils.Must(err)

		if definitionsDir := os.Getenv("NVD_DEFINITIONS_DIR"); definitionsDir != "" {
			log.Info("Loading NVD definitions into cache")
			utils.Must(instance.LoadFromDirectory(definitionsDir))
			log.Info("Done loading NVD definitions into cache")
		}
	})
	return instance
}
