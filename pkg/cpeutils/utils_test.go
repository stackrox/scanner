package cpeutils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetRelatedCPEsForOpenShift4(t *testing.T) {
	testcases := []struct {
		cpe      string
		expected []string
	}{
		{
			cpe: "cpe:/a:redhat:openshift:4.12",
			expected: []string{
				"cpe:/a:redhat:openshift:4.0",
				"cpe:/a:redhat:openshift:4.1",
				"cpe:/a:redhat:openshift:4.2",
				"cpe:/a:redhat:openshift:4.3",
				"cpe:/a:redhat:openshift:4.4",
				"cpe:/a:redhat:openshift:4.5",
				"cpe:/a:redhat:openshift:4.6",
				"cpe:/a:redhat:openshift:4.7",
				"cpe:/a:redhat:openshift:4.8",
				"cpe:/a:redhat:openshift:4.9",
				"cpe:/a:redhat:openshift:4.10",
				"cpe:/a:redhat:openshift:4.11",
			},
		},
		{
			cpe: "cpe:/a:redhat:openshift:4.12::el8",
			expected: []string{
				"cpe:/a:redhat:openshift:4.0::el8",
				"cpe:/a:redhat:openshift:4.1::el8",
				"cpe:/a:redhat:openshift:4.2::el8",
				"cpe:/a:redhat:openshift:4.3::el8",
				"cpe:/a:redhat:openshift:4.4::el8",
				"cpe:/a:redhat:openshift:4.5::el8",
				"cpe:/a:redhat:openshift:4.6::el8",
				"cpe:/a:redhat:openshift:4.7::el8",
				"cpe:/a:redhat:openshift:4.8::el8",
				"cpe:/a:redhat:openshift:4.9::el8",
				"cpe:/a:redhat:openshift:4.10::el8",
				"cpe:/a:redhat:openshift:4.11::el8",
			},
		},
	}
	for _, testcase := range testcases {
		t.Run(testcase.cpe, func(t *testing.T) {
			cpes, err := GetRelatedCPEsForOpenShift4(testcase.cpe)
			assert.NoError(t, err)
			assert.ElementsMatch(t, testcase.expected, cpes)
		})
	}
}
