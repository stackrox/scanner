package orchestratorscan

import (
	"regexp"
	"strings"
	"testing"

	rpmVersion "github.com/knqyf263/go-rpm-version"
	"github.com/stretchr/testify/assert"
)

func TestOpenShiftVulns(t *testing.T) {
	testCases := []*struct {
		version        string
		fixedInVersion string
		expect         int
	}{
		{
			version:        "v3.11.420",
			fixedInVersion: "0:3.11.219-1.git.0.8845382.el7",
			expect:         1,
		},
		{
			version:        "v3.11.211",
			fixedInVersion: "0:3.11.219-1.git.0.8845382.el7",
			expect:         -1,
		},
		{
			version:        "4.2.1",
			fixedInVersion: "0:4.2.20-202002140432.git.1.d9a72a5.el7",
			expect:         -1,
		},
		{
			version:        "4.2.21",
			fixedInVersion: "0:4.2.20-202002140432.git.1.d9a72a5.el7",
			expect:         1,
		},
		{
			version:        "4.2.20",
			fixedInVersion: "0:4.2.20-202002140432.git.1.d9a72a5.el7",
			expect:         0,
		},
	}
	reg := regexp.MustCompile(`^4.5$`)
	assert.Equal(t, true, reg.MatchString("425"))
	for _, c := range testCases {
		version := strings.TrimSpace(c.version)
		version = strings.Trim(version, "v")
		ver := rpmVersion.NewVersion(version)
		version2 := rpmVersion.NewVersion(c.fixedInVersion)
		a := ver.Compare(version2)
		assert.Equal(t, c.expect, a)
	}
}
