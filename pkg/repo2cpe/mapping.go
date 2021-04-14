///////////////////////////////////////////////////
// Influenced by ClairCore under Apache 2.0 License
// https://github.com/quay/claircore
///////////////////////////////////////////////////

package repo2cpe

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
)

const (
	// RHELv2CPERepoName is the name of the JSON file
	// mapping repositories to CPEs.
	RHELv2CPERepoName = "repository-to-cpe.json"
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

func NewMapping() *Mapping {
	m := new(Mapping)
	m.mapping.Store((*RHELv2MappingFile)(nil))

	return m
}

func (m *Mapping) Load(dir string) error {
	path := filepath.Join(dir, RHELv2CPERepoName)
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

func (m *Mapping) Get(repos []string) ([]string, error) {
	if len(repos) == 0 {
		return []string{}, nil
	}

	mapping := m.mapping.Load().(*RHELv2MappingFile)
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
