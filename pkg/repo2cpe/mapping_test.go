package repo2cpe

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stackrox/scanner/pkg/testutils"
	"github.com/stretchr/testify/assert"
)

func TestMapping(t *testing.T) {
	envIsolator := testutils.NewEnvIsolator(t)
	defer envIsolator.RestoreAll()

	_, filename, _, _ := runtime.Caller(0)
	cpesDir := filepath.Join(filepath.Dir(filename), "/testdata")
	envIsolator.Setenv("REPO_TO_CPE_DIR", cpesDir)

	repos := []string{
		"3scale-amp-2-rpms-for-rhel-8-x86_64-debug-rpms",
		"3scale-amp-2-rpms-for-rhel-8-x86_64-rpms",
		"rhel-8-for-x86_64-baseos-rpms",
		"fakerepo",
	}
	expectedCPEs := []string{
		"cpe:/a:redhat:3scale_amp:2.10::el8",
		"cpe:/a:redhat:3scale_amp:2.11::el8",
		"cpe:/a:redhat:3scale_amp:2.8::el8",
		"cpe:/a:redhat:3scale_amp:2.9::el8",
		"cpe:/o:redhat:enterprise_linux:8::baseos",
	}

	m := Singleton()
	cpes, err := m.Get(repos)
	assert.NoError(t, err)
	assert.ElementsMatch(t, cpes, expectedCPEs)
}
