package istioloader

import (
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/pkg/errors"
	"github.com/stackrox/scanner/pkg/vulndump"
	"github.com/stackrox/scanner/pkg/vulnloader"
)

const (
	istioCVEsRepository = "https://github.com/stackrox/istio-cves.git"
	istioCVEsRefName    = "refs/heads/main"
)

func init() {
	vulnloader.RegisterLoader(vulndump.K8sDirName, &loader{})
}

type loader struct{}

func (l loader) DownloadFeedsToPath(outputDir string) error {
	tmpK8sDir := filepath.Join(outputDir, vulndump.K8sDirName+"-tmp")
	if err := os.MkdirAll(tmpK8sDir, 0755); err != nil {
		return errors.Wrapf(err, "creating subdir for %s", tmpK8sDir)
	}

	_, err := git.PlainClone(tmpK8sDir, false, &git.CloneOptions{
		URL:           istioCVEsRepository,
		ReferenceName: istioCVEsRefName,
		SingleBranch:  true,
	})
	if err != nil {
		return err
	}

	return os.Rename(filepath.Join(tmpK8sDir, "cves"), filepath.Join(outputDir, vulndump.K8sDirName))
}
