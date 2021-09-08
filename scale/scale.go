package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/fixtures"
	"github.com/stackrox/rox/pkg/stringutils"
	"github.com/stackrox/rox/pkg/sync"
	"github.com/stackrox/rox/pkg/urlfmt"
	"github.com/stackrox/rox/pkg/utils"
	v1 "github.com/stackrox/scanner/api/v1"
	"github.com/stackrox/scanner/pkg/clairify/client"
	"github.com/stackrox/scanner/pkg/clairify/types"
)

const (
	scannerHTTPEndpointEnv = "SCANNER_ENDPOINT"

	registry = "https://registry-1.docker.io"

	maxConcurrentScans = 4
)

func main() {
	if len(os.Args[1:]) != 1 {
		logrus.Fatal("must specify the directory into which to write profiles via a single argument")
	}
	dir := os.Args[1]
	logrus.Infof("pprof output will be written to %s", dir)

	endpoint := urlfmt.FormatURL(stringutils.OrDefault(os.Getenv(scannerHTTPEndpointEnv), "localhost:8080"), urlfmt.HTTPS, urlfmt.NoTrailingSlash)
	cli := client.New(endpoint, true)

	go profileForever(cli.GetHTTPClient(), endpoint, dir)

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

func profileForever(cli *http.Client, endpoint, dir string) {
	heapReq, heapErr := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/debug/heap", endpoint), nil)
	cpuReq, cpuErr := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/debug/pprof/profile", endpoint), nil)
	goroutineReq, goroutineErr := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/debug/goroutine", endpoint), nil)
	utils.CrashOnError(heapErr, cpuErr, goroutineErr)

	//	Representation of: Mon Jan 2 15:04:05 -0700 MST 2006
	layout := "2006-01-02-15-04-05"
	for {
		heapResp, heapErr := cli.Do(heapReq)
		cpuResp, cpuErr := cli.Do(cpuReq)
		goroutineResp, goroutineErr := cli.Do(goroutineReq)
		utils.CrashOnError(heapErr, cpuErr, goroutineErr)

		now := time.Now()
		heapF, heapErr := os.Create(fmt.Sprintf("%s/heap_%s.tar.gz", dir, now.Format(layout)))
		cpuF, cpuErr := os.Create(fmt.Sprintf("%s/cpu_%s.tar.gz", dir, now.Format(layout)))
		goroutineF, goroutineErr := os.Create(fmt.Sprintf("%s/goroutine_%s.tar.gz", dir, now.Format(layout)))
		utils.CrashOnError(heapErr, cpuErr, goroutineErr)

		_, heapErr = io.Copy(heapF, heapResp.Body)
		_, cpuErr = io.Copy(cpuF, cpuResp.Body)
		_, goroutineErr = io.Copy(goroutineF, goroutineResp.Body)
		utils.CrashOnError(heapErr, cpuErr, goroutineErr)

		time.Sleep(30 * time.Second)
	}
}
