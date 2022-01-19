package main

import (
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stackrox/scanner/api"
	"github.com/stretchr/testify/assert"
)

func TestLoadConfig(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	cfg, err := LoadConfig(filepath.Dir(filename) + "/testdata/config.yaml")
	assert.NoError(t, err)

	assert.Equal(t, &api.Config{
		HTTPSPort:   8082,
		GRPCPort:    8081,
		MetricsPort: nil,
	}, cfg.API)

	assert.Equal(t, 5*time.Minute, cfg.Updater.Interval)
}
