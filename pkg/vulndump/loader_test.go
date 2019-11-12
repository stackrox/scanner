package vulndump

import (
	"fmt"
	"testing"

	"github.com/stackrox/scanner/database"
	"github.com/stretchr/testify/require"
)

func TestLoader(t *testing.T) {
	t.Skip("TODO(viswa): get actual fake data for this")
	var numVulns int
	mockDB := database.MockDatastore{
		FctGetKeyValue: func(key string) (s string, e error) {
			return "", nil
		},
		FctInsertKeyValue: func(key, value string) error {
			return nil
		},
		FctInsertVulnerabilities: func(vulnerabilities []database.Vulnerability) error {
			if numVulns > 0 {
				panic("Multiple writes")
			}
			numVulns = len(vulnerabilities)
			return nil
		},
	}

	require.NoError(t, UpdateFromVulnDump("../../vulndump.tar.gz", &mockDB, func(nvdDefinitionsDir string) error {
		fmt.Println("Got dir", nvdDefinitionsDir)
		return nil
	}))
}
