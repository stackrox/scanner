// Copyright 2017 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/pprof"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/httputil/proxy"
	"github.com/stackrox/rox/pkg/sync"
	"github.com/stackrox/scanner/api"
	"github.com/stackrox/scanner/api/grpc"
	"github.com/stackrox/scanner/api/v1/imagescan"
	"github.com/stackrox/scanner/api/v1/nodescan"
	"github.com/stackrox/scanner/api/v1/orchestratorscan"
	"github.com/stackrox/scanner/api/v1/ping"
	"github.com/stackrox/scanner/api/v1/vulndefs"
	"github.com/stackrox/scanner/cpe/nvdtoolscache"
	"github.com/stackrox/scanner/database"
	k8scache "github.com/stackrox/scanner/k8s/cache"
	"github.com/stackrox/scanner/pkg/clairify/metrics"
	"github.com/stackrox/scanner/pkg/clairify/server"
	"github.com/stackrox/scanner/pkg/env"
	"github.com/stackrox/scanner/pkg/formatter"
	"github.com/stackrox/scanner/pkg/ioutils"
	"github.com/stackrox/scanner/pkg/repo2cpe"
	"github.com/stackrox/scanner/pkg/tarutil"
	"github.com/stackrox/scanner/pkg/updater"
	"github.com/stackrox/scanner/pkg/version"
	"golang.org/x/sys/unix"

	// Register database driver.
	_ "github.com/stackrox/scanner/database/pgsql"

	// Register extensions.
	_ "github.com/stackrox/scanner/ext/featurefmt/apk"
	_ "github.com/stackrox/scanner/ext/featurefmt/dpkg"
	_ "github.com/stackrox/scanner/ext/featurefmt/rpm"
	_ "github.com/stackrox/scanner/ext/featurens/alpinerelease"
	_ "github.com/stackrox/scanner/ext/featurens/aptsources"
	_ "github.com/stackrox/scanner/ext/featurens/busybox"
	_ "github.com/stackrox/scanner/ext/featurens/lsbrelease"
	_ "github.com/stackrox/scanner/ext/featurens/osrelease"
	_ "github.com/stackrox/scanner/ext/featurens/redhatrelease"
	_ "github.com/stackrox/scanner/ext/imagefmt/docker"
	_ "github.com/stackrox/scanner/ext/kernelparser/all"

	// Register validators
	_ "github.com/stackrox/scanner/cpe/validation/all"
)

const (
	proxyConfigPath = "/run/secrets/stackrox.io/proxy-config"
	proxyConfigFile = "config.yaml"
)

func init() {
	proxy.UseWithDefaultTransport()
}

var debugRoutes = map[string]http.Handler{
	"/debug/pprof":         http.HandlerFunc(pprof.Index),
	"/debug/pprof/cmdline": http.HandlerFunc(pprof.Cmdline),
	"/debug/pprof/profile": http.HandlerFunc(pprof.Profile),
	"/debug/pprof/symbol":  http.HandlerFunc(pprof.Symbol),
	"/debug/pprof/trace":   http.HandlerFunc(pprof.Trace),
	"/debug/block":         pprof.Handler(`block`),
	"/debug/goroutine":     pprof.Handler(`goroutine`),
	"/debug/heap":          pprof.Handler(`heap`),
	"/debug/mutex":         pprof.Handler(`mutex`),
	"/debug/threadcreate":  pprof.Handler(`threadcreate`),
}

func waitForSignals(signals ...os.Signal) {
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, signals...)
	<-interrupts
}

// Boot starts a Clair instance with the provided config.
func Boot(config *Config, slimMode bool) {
	rand.Seed(time.Now().UnixNano())

	// Open database and initialize vuln caches in parallel, prior to making the API available.
	var wg sync.WaitGroup

	var db database.Datastore
	wg.Add(1)
	go func() {
		defer wg.Add(-1)
		var err error
		db, err = database.OpenWithRetries(config.Database, 18, 10*time.Second)
		if err != nil {
			log.WithError(err).Fatal("Failed to open database despite multiple retries...")
		}
	}()

	var nvdVulnCache nvdtoolscache.Cache
	var k8sVulnCache k8scache.Cache

	if !slimMode {
		wg.Add(1)
		go func() {
			defer wg.Add(-1)
			nvdVulnCache = nvdtoolscache.Singleton()
		}()

		wg.Add(1)
		go func() {
			defer wg.Add(-1)
			k8sVulnCache = k8scache.Singleton()
		}()
	}

	var repoToCPE *repo2cpe.Mapping

	wg.Add(1)
	go func() {
		defer wg.Add(-1)
		repoToCPE = repo2cpe.Singleton()
	}()

	// Initialize the datastores prior to making the API available
	wg.Wait()
	defer db.Close()

	if slimMode {
		u, err := updater.NewSlimUpdater(config.Updater, config.SensorEndpoint, repoToCPE)
		if err != nil {
			log.WithError(err).Fatal("Failed to initialize slim updater")
		}
		go u.RunForever()
		defer u.Stop()
	} else {
		u, err := updater.New(config.Updater, config.CentralEndpoint, db, repoToCPE, nvdVulnCache, k8sVulnCache)
		if err != nil {
			log.WithError(err).Fatal("Failed to initialize updater")
		}

		// Run the updater once to ensure the BoltDB is synced. One replica will ensure that the postgres DB is up-to-date
		u.UpdateApplicationCachesOnly()

		go u.RunForever()
		defer u.Stop()
	}

	metricsServ := metrics.NewHTTPServer(config.API)
	go metricsServ.RunForever()

	serv := server.New(fmt.Sprintf(":%d", config.API.HTTPSPort), db)
	go api.RunClairify(serv)

	grpcAPI := grpc.NewAPI(grpc.Config{
		Port:         config.API.GRPCPort,
		CustomRoutes: debugRoutes,
	})

	grpcAPI.Register(
		ping.NewService(),
		imagescan.NewService(db, nvdVulnCache),
		orchestratorscan.NewService(db, k8sVulnCache),
		nodescan.NewService(db, nvdVulnCache, k8sVulnCache),
		vulndefs.NewService(db),
	)
	go grpcAPI.Start()

	// Wait for interruption and shutdown gracefully.
	waitForSignals(os.Interrupt, unix.SIGTERM)
	log.Info("Received interruption, gracefully stopping ...")
	// Do not defer this, as we should close the API immediately upon receiving interrupt signal.
	serv.Close()
}

func main() {
	// Parse command-line arguments
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flagConfigPath := flag.String("config", "/etc/scanner/config.yaml", "Load configuration from the specified file.")
	flag.Parse()

	proxy.WatchProxyConfig(context.Background(), proxyConfigPath, proxyConfigFile, true)

	// Check for dependencies.
	for _, bin := range []string{"rpm", "xz"} {
		_, err := exec.LookPath(bin)
		if err != nil {
			log.WithError(err).WithField("dependency", bin).Fatal("failed to find dependency")
		}
	}

	// Load configuration
	config, err := LoadConfig(*flagConfigPath)
	if err != nil {
		log.WithError(err).Fatal("failed to load configuration")
	}

	// Initialize logging system
	logLevel, err := log.ParseLevel(strings.ToUpper(config.LogLevel))
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Invalid log level: %v", err)
		logLevel = log.InfoLevel
	}
	log.SetLevel(logLevel)
	log.SetOutput(os.Stdout)
	log.SetFormatter(&formatter.JSONExtendedFormatter{ShowLn: true})

	// Set the max extractable file size from the config.
	if config.MaxExtractableFileSizeMB > 0 {
		tarutil.SetMaxExtractableFileSize(config.MaxExtractableFileSizeMB * 1024 * 1024)
		log.Infof("Max extractable file size set to %d MB", config.MaxExtractableFileSizeMB)
	}

	// Set the max ELF executable file size from the config.
	if config.MaxELFExecutableFileSizeMB > 0 {
		tarutil.SetMaxELFExecutableFileSize(config.MaxELFExecutableFileSizeMB * 1024 * 1024)
		log.Infof("Max ELF executable file size set to %d MB", config.MaxELFExecutableFileSizeMB)
	}

	// Set the max lazy reader buffer size from the config.
	if config.MaxImageFileReaderBufferSizeMB > 0 {
		tarutil.SetMaxLazyReaderBufferSize(config.MaxImageFileReaderBufferSizeMB * 1024 * 1024)
		log.Infof("Max image file reader buffer size set to %d MB", config.MaxImageFileReaderBufferSizeMB)
	}

	// Cleanup any residue temporary files.
	ioutils.CleanUpTempFiles()

	slimMode := env.SlimMode.Enabled()

	scannerName := "Scanner"
	if slimMode {
		scannerName = "Scanner-Slim"
	}
	log.Infof("Running %s version: %s", scannerName, version.Version)

	Boot(config, slimMode)
}
