package apk

import (
	"errors"
	"strings"

	version "github.com/knqyf263/go-apk-version"
	"github.com/stackrox/scanner/ext/versionfmt"
)

// ParserName is the name by which the apk parser is registered.
const ParserName = "apk"

type parser struct{}

func (p parser) Valid(str string) bool {
	_, err := version.NewVersion(str)
	return err == nil
}

// Compare function compares two Alpine package versions
func (p parser) Compare(a, b string) (int, error) {
	// Quick check
	if a == b {
		return 0, nil
	}

	a = strings.TrimSpace(a)
	if a == "" {
		return 0, errors.New("version string is empty")
	}
	b = strings.TrimSpace(b)
	if b == "" {
		return 0, errors.New("version string is empty")
	}

	if a == versionfmt.MinVersion || b == versionfmt.MaxVersion {
		return -1, nil
	}
	if b == versionfmt.MinVersion || a == versionfmt.MaxVersion {
		return 1, nil
	}

	v1, err := version.NewVersion(a)
	if err != nil {
		return 0, nil
	}

	v2, err := version.NewVersion(b)
	if err != nil {
		return 0, nil
	}

	return v1.Compare(v2), nil
}

func init() {
	versionfmt.RegisterParser(ParserName, parser{})
}
