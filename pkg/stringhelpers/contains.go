package stringhelpers

import "strings"

// AnyContain checks the srcs to see if any contains the tgt and returns true if so
func AnyContain(srcs []string, tgt string) bool {
	for _, s := range srcs {
		if strings.Contains(s, tgt) {
			return true
		}
	}
	return false
}
