package test

import (
	"testing"

	"github.com/stackrox/scanner/ext/versionfmt"
	"github.com/stretchr/testify/assert"

	_ "github.com/stackrox/scanner/ext/versionfmt/apk"
	_ "github.com/stackrox/scanner/ext/versionfmt/dpkg"
	_ "github.com/stackrox/scanner/ext/versionfmt/rpm"
)

func TestGetVersionFormatForNamespace(t *testing.T) {
	assert.Equal(t, "apk", versionfmt.GetVersionFormatForNamespace("alpine:v3.15"))
	assert.Equal(t, "apk", versionfmt.GetVersionFormatForNamespace("alpine"))

	assert.Equal(t, "dpkg", versionfmt.GetVersionFormatForNamespace("debian:11"))
	assert.Equal(t, "dpkg", versionfmt.GetVersionFormatForNamespace("debian"))
	assert.Equal(t, "dpkg", versionfmt.GetVersionFormatForNamespace("ubuntu:14.10"))
	assert.Equal(t, "dpkg", versionfmt.GetVersionFormatForNamespace("ubuntu"))

	assert.Equal(t, "rpm", versionfmt.GetVersionFormatForNamespace("amzn:2018.03"))
	assert.Equal(t, "rpm", versionfmt.GetVersionFormatForNamespace("amzn"))
	assert.Equal(t, "rpm", versionfmt.GetVersionFormatForNamespace("centos:7"))
	assert.Equal(t, "rpm", versionfmt.GetVersionFormatForNamespace("centos"))
	assert.Equal(t, "rpm", versionfmt.GetVersionFormatForNamespace("rhel:8"))
	assert.Equal(t, "rpm", versionfmt.GetVersionFormatForNamespace("rhel"))

	assert.Equal(t, "", versionfmt.GetVersionFormatForNamespace(":"))
}

