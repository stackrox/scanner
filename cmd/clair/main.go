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
	clair "github.com/stackrox/scanner"
	"github.com/stackrox/scanner/api"
	"github.com/stackrox/scanner/api/grpc"
	"github.com/stackrox/scanner/api/v1/scan"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/imagefmt"
	"github.com/stackrox/scanner/pkg/formatter"
	"github.com/stackrox/scanner/pkg/stopper"

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
	_ "github.com/stackrox/scanner/ext/vulnmdsrc/nvd"
	_ "github.com/stackrox/scanner/ext/vulnsrc/alpine"
	_ "github.com/stackrox/scanner/ext/vulnsrc/amzn"
	_ "github.com/stackrox/scanner/ext/vulnsrc/debian"
	_ "github.com/stackrox/scanner/ext/vulnsrc/oracle"
	_ "github.com/stackrox/scanner/ext/vulnsrc/rhel"
	_ "github.com/stackrox/scanner/ext/vulnsrc/ubuntu"
)

func waitForSignals(signals ...os.Signal) {
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, signals...)
	<-interrupts
}

// Boot starts Clair instance with the provided config.
func Boot(config *Config) {
	rand.Seed(time.Now().UnixNano())
	st := stopper.NewStopper()

	// Open database
	var db database.Datastore
	var err error
	for try := 1; ; try++ {
		db, err = database.Open(config.Database)
		if err == nil || try == 5 {
			break
		}
		log.WithError(err).WithField("Attempts", try).Error("Failed to open database. Retrying...")
		time.Sleep(10 * time.Second)
	}

	if err != nil {
		log.WithError(err).Fatal("Failed to open database despite multiple retries...")
	}
	defer db.Close()

	go api.RunClairify(config.API, db)

	grpcAPI := grpc.NewAPI(grpc.Config{
		Port:         config.API.GRPCPort,
		CustomRoutes: debugRoutes,
	})

	grpcAPI.Register(
		scan.NewScanService(db),
	)

	go grpcAPI.Start()

	// Start updater
	st.Begin()
	go clair.RunUpdater(config.Updater, db, st)

	// Wait for interruption and shutdown gracefully.
	waitForSignals(syscall.SIGINT, syscall.SIGTERM)
	log.Info("Received interruption, gracefully stopping ...")
	st.Stop()
}

func main() {
	// Parse command-line arguments
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flagConfigPath := flag.String("config", "/etc/clair/config.yaml", "Load configuration from the specified file.")
	flagLogLevel := flag.String("log-level", "info", "Define the logging level.")
	flagInsecureTLS := flag.Bool("insecure-tls", false, "Disable TLS server's certificate chain and hostname verification when pulling layers.")
	flag.Parse()

	proxy.EnableProxyEnvironmentSetting(true)

	// Check for dependencies.
	for _, bin := range []string{"git", "rpm", "xz"} {
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

	logLevel, err := log.ParseLevel(strings.ToUpper(*flagLogLevel))
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Invalid log level: %v", err)
		logLevel = log.InfoLevel
	}
	log.SetLevel(logLevel)
	log.SetOutput(os.Stdout)
	log.SetFormatter(&formatter.JSONExtendedFormatter{ShowLn: true})

	// Enable TLS server's certificate chain and hostname verification
	// when pulling layers if specified
	if *flagInsecureTLS {
		imagefmt.SetInsecureTLS(*flagInsecureTLS)
	}

	Boot(config)
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
