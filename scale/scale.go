package main

import (
	"os"

	"github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/fixtures"
	"github.com/stackrox/rox/pkg/stringutils"
	"github.com/stackrox/rox/pkg/sync"
	"github.com/stackrox/rox/pkg/urlfmt"
	v1 "github.com/stackrox/scanner/api/v1"
	"github.com/stackrox/scanner/pkg/clairify/client"
	"github.com/stackrox/scanner/pkg/clairify/types"
)

const (
	scannerHTTPEndpointEnv = "SCANNER_ENDPOINT"

	registry = "https://registry-1.docker.io"

	maxConcurrentScans = 4
)

func getScannerHTTPEndpoint() string {
	return urlfmt.FormatURL(stringutils.OrDefault(os.Getenv(scannerHTTPEndpointEnv), "localhost:8080"), urlfmt.HTTPS, urlfmt.NoTrailingSlash)
}

func main() {
	cli := client.New(getScannerHTTPEndpoint(), true)

	var wg sync.WaitGroup
	imagesC := make(chan fixtures.ImageAndID)
	for i := 0; i < maxConcurrentScans; i++ {
		wg.Add(1)
		go func(imagesC <-chan fixtures.ImageAndID) {
			defer wg.Done()

			for image := range imagesC {
				scanImage(cli, &image)
			}
		}(imagesC)
	}

	for _, image := range fixtures.ImageNames {
		imagesC <- image
	}
	close(imagesC)

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
				logrus.WithField("image", image.FullName()).Info("Uncertified image; trying again...")
				continue
			}
		}

		break
	}

	logrus.WithField("image", image.FullName()).Info("Successfully scanned image")
}
