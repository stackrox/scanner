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

func init() {
	// Initialize the singleton as a part of package initialization and not on first call
	// which is inline to a scan
	_ = Singleton()
}

// Singleton returns the cache instance to use.
func Singleton() Cache {
	once.Do(func() {
		var err error
		instance, err = New()
		utils.Must(err)

		if definitionsDir := os.Getenv("NVD_DEFINITIONS_DIR"); definitionsDir != "" {
			log.Info("Loading NVD definitions into cache")
			utils.Must(instance.LoadFromDirectory(definitionsDir))
			log.Info("Done loading NVD definitions into cache")
		}
	})
	return instance
}
