package gem

import (
	"testing"

	"github.com/stackrox/scanner/pkg/analyzer/analyzertest"
	"github.com/stretchr/testify/assert"
)

func TestMatching(t *testing.T) {
	a := Analyzer()
	f := analyzertest.NewFakeFile("usr/local/bundle/specifications/rails-4.2.5.1.gemspec", []byte(validRailsSpec), 0644)
	cs := a.ProcessFile(f.FullPath(), f.FileInfo(), f.Contents())
	assert.Len(t, cs, 1)
}
