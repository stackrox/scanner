package database

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStringMapValueAndScan(t *testing.T) {
	aMap := StringToStringsMap{
		"libc.so.6": {"/usr/bin/mawk": {}},
		"libm.so.6": {"/usr/bin/mawk": {}, "/usr/bin/abcd": {}},
	}
	value, err := aMap.Value()
	assert.NoError(t, err)
	var scanned StringToStringsMap
	assert.NoError(t, scanned.Scan(value.([]byte)))
	assert.Equal(t, scanned, aMap)
}

func TestMerge(t *testing.T) {
	testCases := []struct {
		desc     string
		aMap     StringToStringsMap
		bMap     StringToStringsMap
		expected StringToStringsMap
	} {
		{
			desc: "new libraries and new execs",
			aMap: StringToStringsMap{
				"libc.so.6": {"/usr/bin/mawk": {}},
				"libm.so.6": {"/usr/bin/mawk": {}},
			},
			bMap: StringToStringsMap{
				"libc.so.6": {"/usr/bin/mawk": {}},
				"libm.so.6": {"/usr/bin/abcd": {}},
				"libd.so.1": {"/usr/bin/some": {}},
			},
			expected: StringToStringsMap{
				"libc.so.6": {"/usr/bin/mawk": {}},
				"libm.so.6": {"/usr/bin/mawk": {}, "/usr/bin/abcd": {}},
				"libd.so.1": {"/usr/bin/some": {}},
			},
		},
		{
			desc: "identical",
			aMap: StringToStringsMap{
				"libc.so.6": {"/usr/bin/mawk": {}},
				"libm.so.6": {"/usr/bin/mawk": {}, "/usr/bin/abcd": {}},
			},
			bMap: StringToStringsMap{
				"libc.so.6": {"/usr/bin/mawk": {}},
				"libm.so.6": {"/usr/bin/mawk": {}, "/usr/bin/abcd": {}},
			},
			expected: StringToStringsMap{
				"libc.so.6": {"/usr/bin/mawk": {}},
				"libm.so.6": {"/usr/bin/mawk": {}, "/usr/bin/abcd": {}},
			},
		},
		{
			desc: "merge with nil",
			aMap: StringToStringsMap{
				"libc.so.6": {"/usr/bin/mawk": {}},
				"libm.so.6": {"/usr/bin/mawk": {}, "/usr/bin/abcd": {}},
			},
			bMap: nil,
			expected: StringToStringsMap{
				"libc.so.6": {"/usr/bin/mawk": {}},
				"libm.so.6": {"/usr/bin/mawk": {}, "/usr/bin/abcd": {}},
			},
		},
		{
			desc: "merge from nil",
			aMap: nil,
			bMap: StringToStringsMap{
				"libc.so.6": {"/usr/bin/mawk": {}},
				"libm.so.6": {"/usr/bin/mawk": {}, "/usr/bin/abcd": {}},
			},
			expected: StringToStringsMap{
				"libc.so.6": {"/usr/bin/mawk": {}},
				"libm.so.6": {"/usr/bin/mawk": {}, "/usr/bin/abcd": {}},
			},
		},
	}
	for _, c := range testCases {
		t.Run(c.desc, func(t *testing.T) {
			c.aMap.Merge(c.bMap)
			assert.Equal(t, c.expected, c.aMap)
		})
	}
}
