package k8sloader

import (
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/pkg/errors"
	"github.com/stackrox/scanner/pkg/vulndump"
	"github.com/stackrox/scanner/pkg/vulnloader"
)

const (
	k8sCVEsRepository = "https://github.com:stackrox/k8s-cves.git"
	k8sCVEsRefName    = "refs/heads/main"
)

func init() {
	vulnloader.RegisterLoader(vulndump.K8sDirName, &loader{})
}

type loader struct{}

// DownloadFeedsToPath downloads the Kubernetes feeds to the given path.
func (l *loader) DownloadFeedsToPath(outputDir string) error {
	tmpK8sDir := filepath.Join(outputDir, vulndump.K8sDirName+"-tmp")
	if err := os.MkdirAll(tmpK8sDir, 0755); err != nil {
		return errors.Wrapf(err, "creating subdir for %s", tmpK8sDir)
	}

	_, err := git.PlainClone(tmpK8sDir, false, &git.CloneOptions{
		URL:           k8sCVEsRepository,
		ReferenceName: k8sCVEsRefName,
		SingleBranch:  true,
	})
	if err != nil {
		return err
	}

	return os.Rename(filepath.Join(tmpK8sDir, "cves"), filepath.Join(outputDir, vulndump.K8sDirName))
}
