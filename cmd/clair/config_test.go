package main

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadConfig(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	_, err := LoadConfig(filepath.Dir(filename) + "/testdata/config.yaml")
	assert.NoError(t, err)
}
