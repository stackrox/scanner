package k8sloader

import (
	"context"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/stackrox/scanner/pkg/gitarchive"
	"github.com/stackrox/scanner/pkg/vulndump"
	"github.com/stackrox/scanner/pkg/vulnloader"
)

const (
	k8sCVEsRepository = "https://github.com/stackrox/k8s-cves.git"
	k8sCVEsRef        = "main"
)

func init() {
	vulnloader.RegisterLoader(vulndump.K8sDirName, &loader{})
}

type loader struct{}

// DownloadFeedsToPath downloads the Kubernetes feeds to the given path.
func (l *loader) DownloadFeedsToPath(outputDir string) error {
	ctx := context.Background()

	result, err := gitarchive.Fetch(ctx, gitarchive.FetchOptions{
		RepoURL: k8sCVEsRepository,
		Ref:     k8sCVEsRef,
	})
	if err != nil {
		return errors.Wrap(err, "fetching k8s CVEs archive")
	}
	defer result.Cleanup()

	// GitHub ZIPs have root directory: k8s-cves-main/
	srcDir := "k8s-cves-main/cves"
	destDir := filepath.Join(outputDir, vulndump.K8sDirName)

	if err := gitarchive.ExtractDirectory(result.ZipReader, srcDir, destDir); err != nil {
		return errors.Wrap(err, "extracting cves directory")
	}

	return nil
}
