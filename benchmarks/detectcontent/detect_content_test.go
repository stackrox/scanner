package detectconent

import (
	"testing"

	clair "github.com/stackrox/scanner"
	"github.com/stackrox/scanner/benchmarks"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/tarutil"
	"github.com/stretchr/testify/require"

	// Register the Docker image extractor
	_ "github.com/stackrox/scanner/ext/imagefmt/docker"
)

var (
	// images is a slice of known images with a high number of components.
	// Benchmark tests should not be limited to just these.
	images = []string{
		"centos/nodejs-8-centos7@sha256:3dfd54c57b791d0b8fc4b4670144920e7ad0c1b0bd7a501375af8421d19df90c",
		"splunk/k8s-metrics@sha256:ceb6fdce55ad85055775337960a84faa06d669f08890574e1d7b67b55d4843db",
		"jelastic/apachephp@sha256:90e6bf5d6527ab5e7897a0f26c2abb87a8688ec9213df9bd005b99734e8973df",
		"openshift/wildfly-110-centos7@sha256:5828134f4b215ab02ccc832a5f17f06c5b5d8c71c11f138cd7461e3f246b1929",
		"centos/php-70-centos7@sha256:e8b78ce0bc74a96bef4676126522717f3612e715d18888b1c8c9dbbfb9fa89c8",
		"pivotalservices/pks-kubectl@sha256:2718713093b546902d9b9164f236f9ee23fb31dd6b614203f7839fa4d8fa7161",
		"centos/go-toolset-7-centos7@sha256:f515aea549980c0d2595fc9b7a9cc2e5822be952889a200f2bb9954619ceafe3",
		"cftoolsmiths/deploy-pcf@sha256:fd3e43a69cff154a9b0758ffb60eb574b0c8d4790e88819eadaa73468bc4286e",
	}

	// image is the image used for testing.
	// It may be something in the slice above, or any image one would want to test.
	image = images[0]
)

func BenchmarkDetectContent(b *testing.B) {
	runBenchmarkDetectContent(b, image)
}

func runBenchmarkDetectContent(b *testing.B, imageName string) {
	layers := benchmarks.MustGetLayerReadClosers(b, imageName)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var namespace *database.Namespace
		var err error
		var files *tarutil.LayerFiles
		for _, l := range layers {
			namespace, _, _, _, _, files, err = clair.DetectContentFromReader(l, "Docker", l.Name, &database.Layer{Namespace: namespace}, files, false)
			require.NoError(b, err)
		}
	}
}
