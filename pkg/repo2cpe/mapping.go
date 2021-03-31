package repo2cpe

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"sync/atomic"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/pkg/vulndump"
)

const (
	fileName = "repository-to-cpe.json"
)

type Mapping struct {
	mapping atomic.Value
}

func NewMapping() *Mapping {
	m := new(Mapping)
	m.mapping.Store((*vulndump.RHELv2MappingFile)(nil))

	return m
}

func (m *Mapping) Load(dir string) error {
	path := filepath.Join(dir, fileName)
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return errors.Wrapf(err, "reading mapping file at %s", path)
	}

	var mappingFile vulndump.RHELv2MappingFile
	if err := json.Unmarshal(bytes, &mappingFile); err != nil {
		return errors.Wrapf(err, "unmarshalling mapping file at %s", path)
	}

	m.mapping.Store(&mappingFile)

	return nil
}

func (m *Mapping) Get(repos []string) ([]string, error) {
	if len(repos) == 0 {
		return []string{}, nil
	}

	mapping := m.mapping.Load().(*vulndump.RHELv2MappingFile)
	if mapping == nil {
		return []string{}, nil
	}

	cpes := set.NewStringSet()

	for _, repo := range repos {
		if repoCPEs, ok := mapping.Data[repo]; ok {
			for _, cpe := range repoCPEs.CPEs {
				cpes.Add(cpe)
			}
		} else {
			log.Warnf("Repository %s is not present in the mapping file", repo)
		}
	}

	return cpes.AsSlice(), nil
}
