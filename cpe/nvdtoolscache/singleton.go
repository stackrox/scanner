package nvdtoolscache

import (
	"os"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/pkg/vulnloader/nvdloader"
)

var (
	once     sync.Once
	instance Cache
)

// Singleton returns the cache instance to use.
func Singleton() Cache {
	once.Do(func() {
		enrichmentMap := make(map[string][]*nvdloader.FileFormatWrapper)
		if ghsaGolangDir := os.Getenv("GHSA_GOLANG_DIR"); ghsaGolangDir != "" {
			utils.Must(nvdloader.LoadGolangGHSA(ghsaGolangDir, enrichmentMap))
		}

		var err error
		instance, err = New(enrichmentMap)
		utils.Must(err)

		if definitionsDir := os.Getenv("NVD_DEFINITIONS_DIR"); definitionsDir != "" {
			log.Info("Loading NVD definitions into cache")
			utils.Must(instance.LoadFromDirectory(definitionsDir))
			log.Info("Done loading NVD definitions into cache")
		}
	})
	return instance
}
