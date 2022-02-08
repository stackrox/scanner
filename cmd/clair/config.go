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
	"io"
	"os"
	"time"

	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/api"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/tarutil"
	"github.com/stackrox/scanner/pkg/updater"
	"gopkg.in/yaml.v2"
)

// File represents a YAML configuration file that namespaces all
// configurations under the top-level "scanner" key.
type File struct {
	Scanner Config `yaml:"scanner"`
}

// Config is the global configuration for an instance of Clair.
type Config struct {
	Database                   database.RegistrableComponentConfig `yaml:"database"`
	API                        *api.Config                         `yaml:"api"`
	Updater                    updater.Config                      `yaml:"updater"`
	LogLevel                   string                              `yaml:"logLevel"`
	MaxExtractableFileSizeMB   int64                               `yaml:"maxExtractableFileSizeMB"`
	MaxELFExecutableFileSizeMB int64                               `yaml:"maxELFExecutableFileSizeMB"`
	MaxLazyReaderBufferSizeMB  int64                               `yaml:"maxLazyReaderBufferSizeMB"`

	// CentralEndpoint is the endpoint that central can be reached at. Defaults to https://central.stackrox.svc if not present in the config.
	CentralEndpoint string `yaml:"centralEndpoint"`
}

// DefaultConfig is a configuration that can be used as a fallback value.
func DefaultConfig() Config {
	return Config{
		Database: database.RegistrableComponentConfig{
			Type: "pgsql",
		},
		Updater: updater.Config{
			Interval: 1 * time.Hour,
		},
		API: &api.Config{
			HTTPSPort: 8080,
			GRPCPort:  8443,
		},
		LogLevel:                   "info",
		MaxExtractableFileSizeMB:   tarutil.DefaultMaxExtractableFileSizeMB,
		MaxELFExecutableFileSizeMB: tarutil.DefaultMaxELFExecutableFileSizeMB,
		MaxLazyReaderBufferSizeMB:  tarutil.DefaultMaxLazyReaderBufferSizeMB,
	}
}

// LoadConfig is a shortcut to open a file, read it, and generate a Config.
//
// It supports relative and absolute paths. Given "", it returns DefaultConfig.
func LoadConfig(path string) (config *Config, err error) {
	var cfgFile File
	cfgFile.Scanner = DefaultConfig()
	if path == "" {
		return &cfgFile.Scanner, nil
	}

	f, err := os.Open(os.ExpandEnv(path))
	if err != nil {
		return
	}
	defer utils.IgnoreError(f.Close)

	d, err := io.ReadAll(f)
	if err != nil {
		return
	}

	err = yaml.Unmarshal(d, &cfgFile)
	if err != nil {
		return
	}
	config = &cfgFile.Scanner

	return
}
