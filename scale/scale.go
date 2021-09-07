package main

import (
	"github.com/sirupsen/logrus"
	v1 "github.com/stackrox/scanner/api/v1"
	"os"
	"sync"

	"github.com/stackrox/rox/pkg/fixtures"
	"github.com/stackrox/rox/pkg/stringutils"
	"github.com/stackrox/rox/pkg/urlfmt"
	"github.com/stackrox/scanner/pkg/clairify/client"
	"github.com/stackrox/scanner/pkg/clairify/types"
)

const (
	scannerHTTPEndpointEnv = "SCANNER_ENDPOINT"

	registry = "https://registry-1.docker.io"

	maxConcurrentScans = 4
)

func main() {
	cli := client.New(getScannerHTTPEndpoint(), true)

	var wg sync.WaitGroup
	images := fixtures.GetAllImages()

	for i := 0; i < maxConcurrentScans; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for image := range images {
				scanImage(cli, &image)
			}
		}()
	}

	wg.Wait()
}

func scanImage(cli *client.Clairify, image *fixtures.ImageAndID) {
	for _, b := range []bool{false, true} {
		req := &types.ImageRequest{Image: image.FullName(), Registry: registry, UncertifiedRHELScan: b}

		img, err := cli.AddImage("", "", req)
		if err != nil {
			logrus.WithField("image", image.FullName()).WithError(err).Error("Fatal: unable to scan image")
			return
		}

		env, err := cli.RetrieveImageDataBySHA(img.SHA, &types.GetImageDataOpts{
			UncertifiedRHELResults: b,
		})
		if err != nil {
			logrus.WithField("image", image.FullName()).WithError(err).Error("Fatal: unable to retrieve scan results")
			return
		}

		for _, note := range env.Notes {
			if note == v1.CertifiedRHELScanUnavailable {
				continue
			}
		}

		return
	}

	logrus.WithField("image", image.FullName()).Info("Successfully scanned image")
}

func getScannerHTTPEndpoint() string {
	return urlfmt.FormatURL(stringutils.OrDefault(os.Getenv(scannerHTTPEndpointEnv), "localhost:8080"), urlfmt.HTTPS, urlfmt.NoTrailingSlash)
}
