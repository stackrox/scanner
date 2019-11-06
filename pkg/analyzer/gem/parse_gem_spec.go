package npm

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/pkg/analyzer/internal/common"
	"github.com/stackrox/scanner/pkg/component"
)

var (
	// Example lines:
	//  s.name = "actionmailer".freeze
	//  s.version = "4.2.5.1"
	// Note that s can be any arbitrary identifier.
	nameRegexp    = regexp.MustCompile(`^.*\.name *= *(.*)$`)
	versionRegexp = regexp.MustCompile(`^.*\.version *= *(.*)$`)

	quoteChars = []byte{'"', '\''}
)

// This matches the given regexp (which is either the name regexp or the version regexp above)
// and extracts the matching string value, stripping the surrounding quotes.
func extractStringValueIfLineMatches(re *regexp.Regexp, line string) string {
	matches := re.FindStringSubmatch(line)
	if len(matches) <= 1 {
		return ""
	}
	lastPartOfLine := matches[1]
	// We expect it to have at least an opening and closing quote, and something inside.
	if len(lastPartOfLine) < 3 {
		logrus.Errorf("Gem: invalid line %q; matches regexp %s but has nothing after = sign", line, re.String())
		return ""
	}
	var actualQuoteChar byte
	for _, quoteChar := range quoteChars {
		if lastPartOfLine[0] == quoteChar {
			actualQuoteChar = quoteChar
		}
	}
	if actualQuoteChar == 0 {
		logrus.Errorf("Gem: invalid line %q: does not start with a quote after = sign", line)
		return ""
	}
	var sb strings.Builder
	// Scan over the string and add everything up until the closing quote.
	for i := 1; i < len(lastPartOfLine); i++ {
		if lastPartOfLine[i] == actualQuoteChar {
			break
		}
		sb.WriteByte(lastPartOfLine[i])
	}
	val := sb.String()
	if len(val) == 0 {
		logrus.Errorf("Gem: invalid line %q: empty string specified", line)
		return ""
	}
	return val
}

func parseGemSpec(filePath string, contents []byte) *component.Component {
	var c *component.Component
	ensureCInitialized := func() {
		if c == nil {
			c = &component.Component{
				SourceType: component.GemSourceType,
				Location:   filePath,
			}
		}
	}
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	for scanner.Scan() {
		currentLine := scanner.Text()
		if name := extractStringValueIfLineMatches(nameRegexp, currentLine); name != "" {
			ensureCInitialized()
			c.Name = name
		} else if version := extractStringValueIfLineMatches(versionRegexp, currentLine); version != "" {
			ensureCInitialized()
			c.Version = version
		}
		if common.HasNameAndVersion(c) {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		logrus.Errorf("Error reading file at %q: %v", filePath, err)
		return nil
	}
	// Only send out components where we got both.
	if !common.HasNameAndVersion(c) {
		return nil
	}
	return c
}
