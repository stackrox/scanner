package nvdloader

import (
	"io/ioutil"
	"path/filepath"

	"github.com/ghodss/yaml"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/pkg/errors"
	"github.com/stackrox/dotnet-scraper/types"
)

const (
	nvdEnricherRepo = "git@github.com:stackrox/dotnet-scraper.git"
)

func Fetch() (map[string]*types.FileFormat, error) {
	r, err := git.Clone(memory.NewStorage(), memfs.New(), &git.CloneOptions{
		URL: nvdEnricherRepo,
	})
	if err != nil {
		return nil, errors.Wrap(err, "running git clone")
	}

	w, err := r.Worktree()
	if err != nil {
		return nil, errors.Wrap(err, "getting git worktree")
	}

	// REMOVE BEFORE MERGE
	err = r.Fetch(&git.FetchOptions{
		RefSpecs: []config.RefSpec{"refs/*:refs/*", "HEAD:refs/heads/HEAD"},
	})
	if err != nil {
		panic(err)
	}

	err = w.Checkout(&git.CheckoutOptions{
		Branch: "refs/heads/cgorman-fix-cve",
		Force:  true,
	})

	files, err := w.Filesystem.ReadDir("cves")
	if err != nil {
		return nil, errors.Wrap(err, "reading cve dir")
	}
	resultMap := make(map[string]*types.FileFormat)
	for _, file := range files {
		if filepath.Ext(file.Name()) != ".yaml" {
			continue
		}
		path := filepath.Join("cves", file.Name())
		file, err := w.Filesystem.Open(path)
		if err != nil {
			return nil, errors.Wrapf(err, "opening file: %v", path)
		}
		data, err := ioutil.ReadAll(file)
		if err != nil {
			return nil, errors.Wrapf(err, "reading file: %v", path)
		}
		var ff types.FileFormat
		if err := yaml.Unmarshal(data, &ff); err != nil {
			return nil, errors.Wrapf(err, "unmarshalling file: %v", path)
		}
		resultMap[ff.ID] = &ff
	}
	return resultMap, nil
}
