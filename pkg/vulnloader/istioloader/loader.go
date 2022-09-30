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
	vulnloader.RegisterLoader(vulndump.IstioDirName, &loader{})
}

type loader struct{}

func (l loader) DownloadFeedsToPath(outputDir string) error {
	tmpIstioDir := filepath.Join(outputDir, vulndump.IstioDirName+"-tmp")
	if err := os.MkdirAll(tmpIstioDir, 0755); err != nil {
		return errors.Wrapf(err, "creating subdir for %s", tmpIstioDir)
	}

	_, err := git.PlainClone(tmpIstioDir, false, &git.CloneOptions{
		URL:           istioCVEsRepository,
		ReferenceName: istioCVEsRefName,
		SingleBranch:  true,
	})
	if err != nil {
		return err
	}

	return os.Rename(filepath.Join(tmpIstioDir, "cves"), filepath.Join(outputDir, vulndump.IstioDirName))
}
