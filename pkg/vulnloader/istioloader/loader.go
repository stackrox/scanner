package istioloader

import (
	"context"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/stackrox/scanner/pkg/gitarchive"
	"github.com/stackrox/scanner/pkg/vulndump"
	"github.com/stackrox/scanner/pkg/vulnloader"
)

const (
	istioCVEsRepository = "https://github.com/stackrox/istio-cves.git"
	istioCVEsRef        = "main"
)

func init() {
	vulnloader.RegisterLoader(vulndump.IstioDirName, &loader{})
}

type loader struct{}

func (l loader) DownloadFeedsToPath(outputDir string) error {
	ctx := context.Background()

	result, err := gitarchive.Fetch(ctx, gitarchive.FetchOptions{
		RepoURL: istioCVEsRepository,
		Ref:     istioCVEsRef,
	})
	if err != nil {
		return errors.Wrap(err, "fetching Istio CVEs archive")
	}
	defer result.Cleanup()

	// GitHub ZIPs have root directory: istio-cves-main/
	srcDir := "istio-cves-main/vulns"
	destDir := filepath.Join(outputDir, vulndump.IstioDirName)

	if err := gitarchive.ExtractDirectory(result.ZipReader, srcDir, destDir); err != nil {
		return errors.Wrap(err, "extracting vulns directory")
	}

	return nil
}
