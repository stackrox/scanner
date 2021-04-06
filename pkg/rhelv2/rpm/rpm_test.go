package rpm

import (
	"io/ioutil"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stackrox/scanner/pkg/tarutil"
	"github.com/stretchr/testify/assert"
)

func TestRPMFeatureDetection(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	d, _ := ioutil.ReadFile(filepath.Join(filepath.Dir(filename), "/testdata"))

	_, cpes, err := ListFeatures(tarutil.FilesMap{
		"var/lib/rpm/Packages": d,
	})
	assert.NoError(t, err)
	assert.Empty(t, cpes)
}
