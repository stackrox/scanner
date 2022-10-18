package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/errorhelpers"
	"github.com/stackrox/rox/pkg/fixtures"
	"github.com/stackrox/rox/pkg/httputil/proxy"
	"github.com/stackrox/rox/pkg/sync"
	"github.com/stackrox/rox/pkg/urlfmt"
	"github.com/stackrox/rox/pkg/utils"
	v1 "github.com/stackrox/scanner/api/v1"
	"github.com/stackrox/scanner/pkg/clairify/client"
	"github.com/stackrox/scanner/pkg/clairify/types"
)

const (
	scannerHTTPEndpoint = "localhost:8080"
	scannerGRPCEndpoint = "localhost:8443"
	dialerTimeout       = 2 * time.Second
	clientTimeout       = 5 * time.Minute

	registry = "https://registry-1.docker.io"

	maxConcurrentScans    = 30
	maxAllowedScanFailure = 180
	scanTimeOut           = 8 * time.Minute
)

func main() {
	if len(os.Args[1:]) != 1 {
		logrus.Fatal("must specify the directory into which to write profiles via a single argument")
	}
	dir := os.Args[1]
	logrus.Infof("pprof output will be written to %s", dir)

	dialer := &net.Dialer{Timeout: dialerTimeout}
	httpClient := &http.Client{
		Timeout: clientTimeout,
		Transport: &http.Transport{
			DialContext:     dialer.DialContext,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           proxy.TransportFunc,
		},
	}

	// stopC signals when the profiler should terminate
	// and also indicates when the profiler has terminated.
	stopC := make(chan struct{}, 1)
	go profileForever(httpClient, dir, stopC)

	endpoint := urlfmt.FormatURL(scannerHTTPEndpoint, urlfmt.HTTPS, urlfmt.NoTrailingSlash)
	cli := client.NewWithClient(endpoint, httpClient)
	client.ScanTimeout = scanTimeOut

	// scanFailures is the number of failed image scans.
	// This is a sanity check to validate the test result.
	var scanFailures uint64
	var wg sync.WaitGroup
	imagesC := make(chan fixtures.ImageAndID)
	for i := 0; i < maxConcurrentScans; i++ {
		wg.Add(1)
		go func(imagesC <-chan fixtures.ImageAndID) {
			defer wg.Done()

			for image := range imagesC {
				err := scanImage(cli, &image)
				if err != nil {
					atomic.AddUint64(&scanFailures, 1)
				}
			}
		}(imagesC)
	}

	for _, image := range fixtures.ImageNames[:1800] {
		imagesC <- image
	}
	// Signal there are no more images to scan.
	close(imagesC)

	// Wait for the scan goroutines to terminate.
	wg.Wait()
	// Signal the profiler to terminate.
	stopC <- struct{}{}

	// Wait for profiler to terminate gracefully.
	<-stopC

	if scanFailures > maxAllowedScanFailure {
		err := errors.Errorf("%d (> %d) scans failed.", scanFailures, maxAllowedScanFailure)
		utils.CrashOnError(err)
	}
}

// scanImage scans the given image with the client Clairify client.
func scanImage(cli *client.Clairify, image *fixtures.ImageAndID) error {
	for _, b := range []bool{false, true} {
		req := &types.ImageRequest{Image: image.FullName(), Registry: registry, UncertifiedRHELScan: b}

		img, err := cli.AddImage("", "", req)
		if err != nil {
			logrus.WithField("image", image.FullName()).WithError(err).Error("Unable to scan image")
			return err
		}

		env, err := cli.RetrieveImageDataBySHA(img.SHA, &types.GetImageDataOpts{
			UncertifiedRHELResults: b,
		})
		if err != nil {
			logrus.WithField("image", image.FullName()).WithError(err).Error("Unable to retrieve scan results")
			return err
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
	return nil
}

// profileForever queries the scanner at the given endpoint with the given client
// and saves the contents in the given directory.
// The stopC channel signals the profiler should terminate gracefully.
//
// This function writes to the stopC channel to indicate when it has terminated gracefully.
func profileForever(cli *http.Client, dir string, stopC chan struct{}) {
	endpoint := urlfmt.FormatURL(scannerGRPCEndpoint, urlfmt.HTTPS, urlfmt.NoTrailingSlash)

	heapReq, heapErr := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/debug/heap", endpoint), nil)
	cpuReq, cpuErr := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/debug/pprof/profile", endpoint), nil)
	goroutineReq, goroutineErr := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/debug/goroutine", endpoint), nil)
	utils.CrashOnError(heapErr, cpuErr, goroutineErr)

	// Representation of: Mon Jan 2 15:04:05 -0700 MST 2006
	layout := "2006-01-02-15-04-05"
	for {
		select {
		case <-stopC:
			stopC <- struct{}{}
			return
		default:
		}

		heapResp, heapErr := cli.Do(heapReq)
		cpuResp, cpuErr := cli.Do(cpuReq)
		goroutineResp, goroutineErr := cli.Do(goroutineReq)
		if heapErr != nil || cpuErr != nil || goroutineErr != nil {
			errors := errorhelpers.NewErrorListWithErrors("retrieving Scanner profiles", []error{heapErr, cpuErr, goroutineErr})
			logrus.Fatalf("unable to get profile(s) from Scanner: %v", errors.ToError())
		}

		now := time.Now()
		heapF, heapErr := os.Create(fmt.Sprintf("%s/heap_%s.tar.gz", dir, now.Format(layout)))
		cpuF, cpuErr := os.Create(fmt.Sprintf("%s/cpu_%s.tar.gz", dir, now.Format(layout)))
		goroutineF, goroutineErr := os.Create(fmt.Sprintf("%s/goroutine_%s.tar.gz", dir, now.Format(layout)))
		utils.CrashOnError(heapErr, cpuErr, goroutineErr)

		_, heapErr = io.Copy(heapF, heapResp.Body)
		_, cpuErr = io.Copy(cpuF, cpuResp.Body)
		_, goroutineErr = io.Copy(goroutineF, goroutineResp.Body)
		utils.CrashOnError(heapErr, cpuErr, goroutineErr)

		utils.IgnoreError(heapF.Close)
		utils.IgnoreError(cpuF.Close)
		utils.IgnoreError(goroutineF.Close)

		time.Sleep(30 * time.Second)
	}
}
