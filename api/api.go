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

package api

import (
	"fmt"
	"net/http"
	"net/http/pprof"
	"time"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/clairify/server"
	"github.com/stackrox/scanner/pkg/clairify/types"
	"github.com/stackrox/scanner/pkg/stopper"
	"github.com/tylerb/graceful"
)

// Config is the configuration for the API service.
type Config struct {
	HealthPort                int
	ClairifyPort              int
	MTLS                      bool
	Timeout                   time.Duration
	PaginationKey             string
	CertFile, KeyFile, CAFile string
}

func RunClairify(cfg *Config, store database.Datastore) {
	serv := server.New(fmt.Sprintf(":%d", cfg.ClairifyPort), store, types.DockerRegistryCreator, types.InsecureDockerRegistryCreator)
	if err := serv.Start(cfg.MTLS); err != nil {
		log.Fatal(err)
	}
}

func RunDebug(cfg *Config, st *stopper.Stopper) {
	defer st.End()

	log.WithField("port", "6062").Info("starting debug API")

	srv := &graceful.Server{
		Timeout:          10 * time.Second, // Interrupt health checks when stopping
		NoSignalHandling: true,             // We want to use our own Stopper
		Server: &http.Server{
			Addr:    "127.0.0.1:6062",
			Handler: http.TimeoutHandler(newDebugHandler(), cfg.Timeout, timeoutResponse),
		},
	}

	listenAndServeWithStopper(srv, st, "", "")

	log.Info("debug API stopped")
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

func newDebugHandler() http.Handler {
	router := httprouter.New()
	for route, handler := range debugRoutes {
		router.Handler(http.MethodGet, route, handler)
	}
	return router
}
