package convert

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTruncateVersion(t *testing.T) {
	for _, testCase := range []struct {
		version  string
		expected string
	}{
		{
			version:  "1.0.0",
			expected: "1.0.0",
		},
		{
			version:  "v1.0.0",
			expected: "1.0.0",
		},
		{
			version:  "v1.11.0+d4cacc0",
			expected: "1.11.0",
		},
		{
			version:  "19.3.5",
			expected: "19.3.5",
		},
		{
			version:  "1.11.13-1.rhaos3.11.gitfb88a9c.el7",
			expected: "1.11.13",
		},
		{
			version:  "3.10.0-1127.13.1.el7.x86_64",
			expected: "3.10.0",
		},
		{
			version:  "5.4.0-1027-gke",
			expected: "5.4.0",
		},
		{
			version:  "4.19.112+",
			expected: "4.19.112",
		},
		{
			version:  "v1.17.12-eks-7684af",
			expected: "1.17.12",
		},
		{
			version:  "4.14.203-156.332.amzn2.x86_64",
			expected: "4.14.203",
		},
		{
			version:  "5.4.83-flatcar",
			expected: "5.4.83",
		},
		{
			version:  "5.4.0-5-cloud-amd64",
			expected: "5.4.0",
		},
		{
			version:  "4.19.123-coreos",
			expected: "4.19.123",
		},
		{
			version:  "4.7.0-202104090228.p0.git.97111.77863f8.el7",
			expected: "4.7.0",
		},
		{
			version:  "0:4.7.0-202104030128.p0-2513fdb",
			expected: "4.7.0",
		},
		{
			version:  "1.20.6-7.rhaos4.7.gitd7f3909.el8",
			expected: "1.20.6",
		},
	} {
		actual, err := TruncateVersion(testCase.version)
		assert.NoError(t, err)
		assert.Equal(t, testCase.expected, actual)
	}
}
