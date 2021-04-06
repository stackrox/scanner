package repo2cpe

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/pkg/errors"
)

const (
	fileName = "repository-to-cpe.json"
)

// RHELv2MappingFile is a data struct for mapping file between repositories and CPEs
type RHELv2MappingFile struct {
	Data map[string]RHELv2Repo `json:"data"`
}

// RHELv2Repo structure holds information about CPEs for given repo
type RHELv2Repo struct {
	CPEs []string `json:"cpes"`
}

type Mapping struct {
	mapping atomic.Value
}

func (m *Mapping) Load(dir string) error {
	path := filepath.Join(dir, fileName)
	bytes, err := os.ReadFile(path)
	if err != nil {
		return errors.Wrapf(err, "reading mapping file at %s", path)
	}

	var mappingFile RHELv2MappingFile
	if err := json.Unmarshal(bytes, &mappingFile); err != nil {
		return errors.Wrapf(err, "unmarshalling mapping file at %s", path)
	}

	m.mapping.Store(&mappingFile)

	return nil
}
