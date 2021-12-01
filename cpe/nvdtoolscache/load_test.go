package nvdtoolscache

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCPEIsApplicationOrLinuxKernel(t *testing.T) {
	assert.True(t, cpeIsApplicationOrLinuxKernel("cpe:2.3:a:netapp:snapmanager:-:*:*:*:*:oracle:*:*"))
	assert.True(t, cpeIsApplicationOrLinuxKernel("cpe:2.3:o:linux:linux_kernel:5:*:*:*:*:*:*:*"))
	assert.False(t, cpeIsApplicationOrLinuxKernel("cpe:2.3:o:fedoraproject:fedora:35:*:*:*:*:*:*:*"))
	assert.False(t, cpeIsApplicationOrLinuxKernel("cpe:2.3:a:oracle:*:14.3.0:*:*:*:*:*:*:*"))
	assert.False(t, cpeIsApplicationOrLinuxKernel("cpe:2.3:a:oracle::14.3.0:*:*:*:*:*:*:*"))
	assert.False(t, cpeIsApplicationOrLinuxKernel("cpe:2.3:invalid"))
}
