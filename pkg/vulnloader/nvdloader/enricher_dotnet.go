package nvdloader

import (
	"io"
	"path/filepath"

	"github.com/facebookincubator/nvdtools/vulndb"
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

// FetchDotnet fetches .NET and ASP.NET vulnerabilities from their source.
func FetchDotnet(enrichmentMap map[string][]*FileFormatWrapper) error {
	r, err := git.Clone(memory.NewStorage(), memfs.New(), &git.CloneOptions{
		URL: nvdEnricherRepo,
	})
	if err != nil {
		return errors.Wrap(err, "running git clone")
	}

	w, err := r.Worktree()
	if err != nil {
		return errors.Wrap(err, "getting git worktree")
	}

	files, err := w.Filesystem.ReadDir("cves")
	if err != nil {
		return errors.Wrap(err, "reading cve dir")
	}
	for _, file := range files {
		if filepath.Ext(file.Name()) != ".yaml" {
			continue
		}
		path := filepath.Join("cves", file.Name())

		iter, err := r.Log(&git.LogOptions{
			FileName: &path,
			Order:    git.LogOrderCommitterTime,
		})
		if err != nil {
			return errors.Wrapf(err, "running git log for file: %v", path)
		}
		c, err := iter.Next()
		if err != nil {
			return errors.Wrapf(err, "getting the latest commit for file: %v", path)
		}
		if c == nil || c.Committer.When.IsZero() {
			return errors.Errorf("latest found commit for %v is nil or does not have valid time", path)
		}

		file, err := w.Filesystem.Open(path)
		if err != nil {
			return errors.Wrapf(err, "opening file: %v", path)
		}
		data, err := io.ReadAll(file)
		if err != nil {
			return errors.Wrapf(err, "reading file: %v", path)
		}
		var ff types.FileFormat
		if err := yaml.Unmarshal(data, &ff); err != nil {
			return errors.Wrapf(err, "unmarshalling file: %v", path)
		}
		enrichmentMap[ff.ID] = append(enrichmentMap[ff.ID], &FileFormatWrapper{
			LastUpdated: c.Committer.When.Format(vulndb.TimeLayout),
			FileFormat:  ff,
		})
	}
	return nil
}
