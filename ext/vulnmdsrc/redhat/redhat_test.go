package redhat

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stackrox/scanner/ext/vulnmdsrc"
	"github.com/stretchr/testify/assert"
)

func TestRedHatParser(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(filename))

	dataFilePath := filepath.Join(path, "/testdata/redhat_test.json")
	testData, err := os.Open(dataFilePath)
	if err != nil {
		t.Fatalf("Error opening %q: %v", dataFilePath, err)
	}
	defer testData.Close()

	a := &appender{}
	a.metadata = make(map[string]*metadataEnricher)

	err = a.parseDataFeed(testData)
	if err != nil {
		t.Fatalf("Error parsing %q: %v", dataFilePath, err)
	}

	// CVEs with CVSSv2, CVSSv3, or both should be returned.
	assert.Len(t, a.metadata, 4)
	_, ok := a.metadata["CVE-2002-0001"]
	assert.False(t, ok)

	// Item with only CVSSv2.
	gotMetadata, ok := a.metadata["CVE-2012-0001"]
	assert.True(t, ok)
	wantMetadata := &vulnmdsrc.Metadata{
		CVSSv2: vulnmdsrc.MetadataCVSSv2{
			Vectors:             "AV:N/AC:L/Au:S/C:P/I:N/A:N",
			Score:               4.0,
			ExploitabilityScore: 8.0,
			ImpactScore:         2.9,
		},
	}
	assert.Equal(t, wantMetadata, gotMetadata.Metadata())

	// Item with only CVSSv3.
	gotMetadata, ok = a.metadata["CVE-2012-0002"]
	assert.True(t, ok)
	wantMetadata = &vulnmdsrc.Metadata{
		CVSSv3: vulnmdsrc.MetadataCVSSv3{
			Vectors:             "CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:H",
			Score:               4.6,
			ExploitabilityScore: 0.4,
			ImpactScore:         4.2,
		},
	}
	assert.Equal(t, wantMetadata, gotMetadata.Metadata())

	// Item with both CVSSv2 and CVSSv3 has CVSSv2 information returned.
	gotMetadata, ok = a.metadata["CVE-2018-0001"]
	assert.True(t, ok)
	wantMetadata = &vulnmdsrc.Metadata{
		CVSSv2: vulnmdsrc.MetadataCVSSv2{
			Vectors:             "AV:N/AC:L/Au:N/C:P/I:P/A:P",
			Score:               7.5,
			ExploitabilityScore: 10.0,
			ImpactScore:         6.4,
		},
		CVSSv3: vulnmdsrc.MetadataCVSSv3{
			Vectors:             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Score:               9.8,
			ExploitabilityScore: 3.9,
			ImpactScore:         5.9,
		},
	}
	assert.Equal(t, wantMetadata, gotMetadata.Metadata())

	// float CVSS instead of string
	gotMetadata, ok = a.metadata["CVE-2014-4715"]
	assert.True(t, ok)
	wantMetadata = &vulnmdsrc.Metadata{
		PublishedDateTime: "2014-07-03T00:00:00Z",
		CVSSv2: vulnmdsrc.MetadataCVSSv2{
			Vectors:             "AV:L/AC:H/Au:S/C:C/I:C/A:C",
			Score:               6.0,
			ExploitabilityScore: 1.5,
			ImpactScore:         10.0,
		},
	}
	assert.Equal(t, wantMetadata, gotMetadata.Metadata())
}

func TestNVDParserErrors(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(filename))

	dataFilePath := filepath.Join(path, "/testdata/redhat_test_incorrect_format.json")
	testData, err := os.Open(dataFilePath)
	if err != nil {
		t.Fatalf("Error opening %q: %v", dataFilePath, err)
	}
	defer testData.Close()

	a := &appender{}
	a.metadata = make(map[string]*metadataEnricher)

	err = a.parseDataFeed(testData)
	if err == nil {
		t.Fatalf("Expected error parsing Red Hat data file: %q", dataFilePath)
	}
}
