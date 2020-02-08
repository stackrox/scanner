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
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/httputil/proxy"
	"github.com/stackrox/rox/pkg/sync"
	"github.com/stackrox/scanner/api"
	"github.com/stackrox/scanner/api/grpc"
	"github.com/stackrox/scanner/api/v1/ping"
	"github.com/stackrox/scanner/api/v1/scan"
	"github.com/stackrox/scanner/cpe/nvdtoolscache"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/imagefmt"
	"github.com/stackrox/scanner/pkg/clairify/server"
	"github.com/stackrox/scanner/pkg/clairify/types"
	"github.com/stackrox/scanner/pkg/formatter"
	"github.com/stackrox/scanner/pkg/stopper"
	"github.com/stackrox/scanner/pkg/tarutil"
	"github.com/stackrox/scanner/pkg/updater"

	// Register database driver.
	_ "github.com/stackrox/scanner/database/pgsql"

	// Register extensions.
	_ "github.com/stackrox/scanner/ext/featurefmt/apk"
	_ "github.com/stackrox/scanner/ext/featurefmt/dpkg"
	_ "github.com/stackrox/scanner/ext/featurefmt/rpm"
	_ "github.com/stackrox/scanner/ext/featurens/alpinerelease"
	_ "github.com/stackrox/scanner/ext/featurens/aptsources"
	_ "github.com/stackrox/scanner/ext/featurens/lsbrelease"
	_ "github.com/stackrox/scanner/ext/featurens/osrelease"
	_ "github.com/stackrox/scanner/ext/featurens/redhatrelease"
	_ "github.com/stackrox/scanner/ext/imagefmt/docker"

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

// Boot starts Clair instance with the provided config.
func Boot(config *Config) {
	rand.Seed(time.Now().UnixNano())
	st := stopper.NewStopper()

	// Open database and initialize vuln cache in parallel, prior to making the API available.
	var wg sync.WaitGroup

	var db database.Datastore
	wg.Add(1)
	go func() {
		defer wg.Add(-1)
		var err error
		db, err = database.OpenWithRetries(config.Database, 10, 10*time.Second)
		if err != nil {
			log.WithError(err).Fatal("Failed to open database despite multiple retries...")
		}
	}()

	var vulncache nvdtoolscache.Cache
	wg.Add(1)
	go func() {
		defer wg.Add(-1)
		vulncache = nvdtoolscache.Singleton()
	}()

	// Initialize the vulnerability cache prior to making the API available
	wg.Wait()
	defer db.Close()

	u, err := updater.New(config.Updater, db, vulncache)
	if err != nil {
		log.WithError(err).Fatal("Failed to initialize updater")
	}

	// Run the updater once to ensure the BoltDB is synced. One replica will ensure that the postgres DB is up to date
	u.UpdateNVDCacheOnly()

	serv := server.New(fmt.Sprintf(":%d", config.API.HTTPSPort), db, types.DockerRegistryCreator, types.InsecureDockerRegistryCreator)
	go api.RunClairify(serv)

	grpcAPI := grpc.NewAPI(grpc.Config{
		Port:         config.API.GRPCPort,
		CustomRoutes: debugRoutes,
	})

	grpcAPI.Register(
		ping.NewService(),
		scan.NewService(db),
	)

	go grpcAPI.Start()

	go u.RunForever()

	// Wait for interruption and shutdown gracefully.
	waitForSignals(syscall.SIGINT, syscall.SIGTERM)
	log.Info("Received interruption, gracefully stopping ...")
	serv.Close()
	st.Stop()
	u.Stop()
}

func main() {
	// Parse command-line arguments
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flagConfigPath := flag.String("config", "/etc/scanner/config.yaml", "Load configuration from the specified file.")
	flagInsecureTLS := flag.Bool("insecure-tls", true, "Disable TLS server's certificate chain and hostname verification when pulling layers.")
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

	// Enable TLS server's certificate chain and hostname verification
	// when pulling layers if specified
	if *flagInsecureTLS {
		imagefmt.SetInsecureTLS(*flagInsecureTLS)
	}

	Boot(config)
}
