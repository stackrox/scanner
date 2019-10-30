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

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/clairify/server"
	"github.com/stackrox/scanner/pkg/clairify/types"
)

// Config is the configuration for the API service.
type Config struct {
	ClairifyPort int
	GRPCPort     int
}

func RunClairify(cfg *Config, store database.Datastore) {
	serv := server.New(fmt.Sprintf(":%d", cfg.ClairifyPort), store, types.DockerRegistryCreator, types.InsecureDockerRegistryCreator)
	if err := serv.Start(); err != nil {
		log.Fatal(err)
	}
}
