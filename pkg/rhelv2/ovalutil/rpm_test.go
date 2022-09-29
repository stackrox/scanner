///////////////////////////////////////////////////
// Influenced by ClairCore under Apache 2.0 License
// https://github.com/quay/claircore
///////////////////////////////////////////////////

package ovalutil

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/quay/goval-parser/oval"
	"github.com/stackrox/scanner/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type definitionTypeTestCase struct {
	def        oval.Definition
	want, name string
	err        bool
}

func simpleProtoVulnFunc(def oval.Definition) (*database.RHELv2Vulnerability, error) {
	return &database.RHELv2Vulnerability{
		Name: def.References[0].RefID,
	}, nil
}

func TestGetDefinitionType(t *testing.T) {
	testCases := []definitionTypeTestCase{
		{
			def:  oval.Definition{ID: "oval:com.redhat.cve:def:20162166"},
			want: CVEDefinition,
			err:  false,
			name: "CVE",
		},
		{
			def:  oval.Definition{ID: "oval:com.redhat.unaffected:def:202014340"},
			want: UnaffectedDefinition,
			err:  false,
			name: "unaffected",
		},
		{
			def:  oval.Definition{ID: "oval:com.redhat.rhsa:def:20190966"},
			want: RHSADefinition,
			err:  false,
			name: "RHSA",
		},
		{
			def:  oval.Definition{ID: "oval:com.redhat.rhba:def:20193384"},
			want: RHBADefinition,
			err:  false,
			name: "RHBA",
		},
		{
			def:  oval.Definition{ID: "oval:com.redhat.rhea:def:20193845"},
			want: RHEADefinition,
			err:  false,
			name: "RHEA",
		},
		{
			def:  oval.Definition{ID: "oval:com.redhat.rhea::20193845"},
			want: "",
			err:  true,
			name: "malformed definition",
		},
		{
			def:  oval.Definition{ID: ""},
			want: "",
			err:  true,
			name: "empty ID",
		},
	}

	for _, tc := range testCases {
		got, err := GetDefinitionType(tc.def)
		if !tc.err && err != nil {
			t.Errorf("%q returned error while it shouldn't", tc.name)
		}
		if tc.err && err == nil {
			t.Errorf("%q didn't return error while it should", tc.name)
		}
		if tc.want != got {
			t.Errorf("%q failed: want %q, got %q", tc.name, tc.want, got)
		}
	}
}

func TestGetPackageResolutions_length(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	path := filepath.Dir(filename)

	dataFilePath := filepath.Join(path, "/testdata/oval.xml")
	f, err := os.Open(dataFilePath)
	require.NoError(t, err)
	defer f.Close()

	var root oval.Root
	require.NoError(t, xml.NewDecoder(f).Decode(&root))

	definitions := root.Definitions.Definitions
	nDefinitions := len(definitions)
	assert.Lenf(t, definitions, 4, "Definition list length is incorrect, current definition list size is: %d", nDefinitions)

	expectedNumResolutions := []int{1, 9, 1, 159}
	for i := 0; i < nDefinitions; i++ {
		pkgResolutions := getPackageResolutions(definitions[i])
		assert.Equal(t, expectedNumResolutions[i], len(pkgResolutions))
	}
}
