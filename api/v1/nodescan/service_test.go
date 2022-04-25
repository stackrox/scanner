package nodescan

import (
	"fmt"
	"testing"

	"github.com/stackrox/scanner/ext/kernelparser"
	"github.com/stretchr/testify/assert"

	// Register kernel parsers.
	_ "github.com/stackrox/scanner/ext/kernelparser/all"
)

func TestNormalizeDocker(t *testing.T) {
	cases := []struct {
		input  string
		output string
	}{
		{
			input:  "1.12",
			output: "1.12",
		},
		{
			input:  "19.03",
			output: "19.03",
		},
		{
			input:  "19.03.5",
			output: "19.03.5",
		},
		{
			input:  "19.3.5",
			output: "19.03.5",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.input, func(t *testing.T) {
			assert.Equal(t, normalizeDocker(testCase.input), testCase.output)
		})
	}
}

func TestParseLinuxKernel(t *testing.T) {
	cases := []struct {
		osImage       string
		kernelVersion string

		match *kernelparser.ParseMatch
		err   error
	}{
		{
			osImage:       "Garden Linux 184.0",
			kernelVersion: "5.4.0-5-cloud-amd64",

			match: &kernelparser.ParseMatch{
				Namespace:   "debian:11",
				Format:      "dpkg",
				FeatureName: "linux",
				Version:     "5.4.0-5-cloud-amd64",
			},
		},
		{
			osImage:       "Debian GNU/Linux 9 (stretch)",
			kernelVersion: "4.9.0-3-amd64",

			match: &kernelparser.ParseMatch{
				Namespace:   "debian:9",
				Format:      "dpkg",
				FeatureName: "linux",
				Version:     "4.9.0-3-amd64",
			},
		},
		{
			osImage:       "Debian GNU/Linux",
			kernelVersion: "4.9.0-3-amd64",

			err: fmt.Errorf("could not find Debian version in OS string: %q", "debian gnu/linux"),
		},
		{
			osImage:       "Red Hat Enterprise Linux CoreOS 45.82.202008101249-0 (Ootpa)",
			kernelVersion: "4.18.0-193.14.3.el8_2.x86_64",

			err: kernelparser.ErrNodeUnsupported,
		},
		{
			osImage:       "Red Hat Enterprise Linux",
			kernelVersion: "4.18.0-193.14.3.el",

			err: fmt.Errorf("could not find RHEL version in kernel version string: %q", "red hat enterprise linux"),
		},
	}

	s := &serviceImpl{}

	for _, testCase := range cases {
		testName := fmt.Sprintf("%s - %s", testCase.osImage, testCase.kernelVersion)
		t.Run(testName, func(t *testing.T) {
			match, err := s.parseLinuxKernel(testCase.osImage, testCase.kernelVersion)

			assert.Equal(t, testCase.match, match)
			assert.Equal(t, testCase.err, err)
		})
	}
}
