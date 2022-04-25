package cos

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stackrox/scanner/ext/kernelparser"
	"github.com/stretchr/testify/assert"
)

func TestParser(t *testing.T) {
	cases := []struct {
		kernelVersion string
		osImage       string
		err           error
	}{
		{
			kernelVersion: "5.10.101+",
			osImage:       "Container-Optimized OS from Google",

			err: kernelparser.ErrKernelUnsupported,
		},
		{
			kernelVersion: "4.18.0-193.14.3.el8_2.x86_64",
			osImage:       "Red Hat Enterprise Linux CoreOS 45.82.202008101249-0 (Ootpa)",

			err: kernelparser.ErrKernelUnrecognized,
		},
	}

	for _, c := range cases {
		t.Run(fmt.Sprintf("%s-%s", c.kernelVersion, c.osImage), func(t *testing.T) {
			osImage := strings.ToLower(c.osImage)

			match, err := parser(nil, c.kernelVersion, osImage)
			assert.Nil(t, match)
			assert.Equal(t, c.err, err)
		})
	}
}
