package k8sloader

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/pkg/errors"
	"github.com/stackrox/scanner/pkg/vulndump"
	"github.com/stackrox/scanner/pkg/vulnloader"
)

const (
	k8sCVEsRepository = "git@github.com:stackrox/k8s-cves.git"
)

func init() {
	vulnloader.RegisterLoader(vulndump.K8sDirName, &loader{})
}

type loader struct{}

// DownloadFeedsToPath downloads the Kubernetes feeds to the given path.
func (l *loader) DownloadFeedsToPath(outputDir string) error {
	k8sDir := filepath.Join(outputDir, vulndump.K8sDirName)
	if err := os.MkdirAll(k8sDir, 0755); err != nil {
		return errors.Wrapf(err, "creating subdir for %s", vulndump.K8sDirName)
	}

	_, err := git.PlainClone(k8sDir, false, &git.CloneOptions{
		URL:           k8sCVEsRepository,
		ReferenceName: "refs/heads/ross-init-cves",
		SingleBranch:  true,
	})

	_ = filepath.Walk(k8sDir, func(path string, info os.FileInfo, err error) error {
		fmt.Println(path)
		return nil
	})

	return err
}
