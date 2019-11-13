package nvdtoolscache

import (
	"os"
	"sync"

	"github.com/stackrox/rox/pkg/utils"
)

var (
	lock       sync.RWMutex
	dbInstance DB
)

func Get() DB {
	lock.RLock()
	defer lock.RUnlock()
	return dbInstance
}

func setInstances(db DB) {
	lock.Lock()
	defer lock.Unlock()
	dbInstance = db
}

func init() {
	definitionsDir := os.Getenv("NVD_DEFINITIONS_DIR")
	if definitionsDir == "" {
		return
	}
	utils.Must(LoadFromDirectory(definitionsDir))

}
