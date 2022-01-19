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
	"net/http"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/pkg/clairify/server"
)

// Config is the configuration for the API service.
// Any updates to this should be tested in cmd/clair/config_test.go.
type Config struct {
	HTTPSPort   int  `yaml:"httpsPort"`
	GRPCPort    int  `yaml:"grpcPort"`
	MetricsPort *int `yaml:"metricsPort"`
}

// RunClairify runs the main Scanner API server.
func RunClairify(serv *server.Server) {
	if err := serv.Start(); err != nil {
		if err != http.ErrServerClosed {
			// (*http.Server).Shutdown was not called, and there is something truly wrong.
			log.Fatal(err)
		}

		// (*http.Server).Shutdown causes (*http.Server).Serve to return http.ErrServerClosed.
		// This is ok, and we should let the scanner shutdown gracefully.
		log.Info(err)
	}
}
