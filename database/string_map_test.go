package database

import (
	"testing"

	"github.com/stackrox/rox/pkg/set"
	"github.com/stretchr/testify/assert"
)

func TestStringMapValueAndScan(t *testing.T) {
	aMap := StringToStringsMap{
		"libc.so.6": set.NewStringSet("/usr/bin/mawk"),
		"libm.so.6": set.NewStringSet("/usr/bin/mawk", "/usr/bin/abcd"),
	}
	stringMapValueAndScan(t, aMap)
	var nilMap StringToStringsMap
	stringMapValueAndScan(t, nilMap)
}

func stringMapValueAndScan(t *testing.T, aMap StringToStringsMap) {
	value, err := aMap.Value()
	assert.NoError(t, err)
	var scanned StringToStringsMap
	assert.NoError(t, scanned.Scan(value.([]byte)))
	assert.Equal(t, aMap, scanned)
}

func TestMerge(t *testing.T) {
	testCases := []struct {
		desc     string
		aMap     StringToStringsMap
		bMap     StringToStringsMap
		expected StringToStringsMap
		updated  bool
	}{
		{
			desc: "new libraries and new execs",
			aMap: StringToStringsMap{
				"libc.so.6": set.NewStringSet("/usr/bin/mawk"),
				"libm.so.6": set.NewStringSet("/usr/bin/mawk"),
			},
			bMap: StringToStringsMap{
				"libc.so.6": set.NewStringSet("/usr/bin/mawk"),
				"libm.so.6": set.NewStringSet("/usr/bin/abcd"),
				"libd.so.1": set.NewStringSet("/usr/bin/some"),
			},
			expected: StringToStringsMap{
				"libc.so.6": set.NewStringSet("/usr/bin/mawk"),
				"libm.so.6": set.NewStringSet("/usr/bin/mawk", "/usr/bin/abcd"),
				"libd.so.1": set.NewStringSet("/usr/bin/some"),
			},
			updated: true,
		},
		{
			desc: "identical",
			aMap: StringToStringsMap{
				"libc.so.6": set.NewStringSet("/usr/bin/mawk"),
				"libm.so.6": set.NewStringSet("/usr/bin/mawk", "/usr/bin/abcd"),
			},
			bMap: StringToStringsMap{
				"libc.so.6": set.NewStringSet("/usr/bin/mawk"),
				"libm.so.6": set.NewStringSet("/usr/bin/mawk", "/usr/bin/abcd"),
			},
			expected: StringToStringsMap{
				"libc.so.6": set.NewStringSet("/usr/bin/mawk"),
				"libm.so.6": set.NewStringSet("/usr/bin/mawk", "/usr/bin/abcd"),
			},
			updated: false,
		},
		{
			desc: "merge with nil",
			aMap: StringToStringsMap{
				"libc.so.6": set.NewStringSet("/usr/bin/mawk"),
				"libm.so.6": set.NewStringSet("/usr/bin/mawk", "/usr/bin/abcd"),
			},
			bMap: nil,
			expected: StringToStringsMap{
				"libc.so.6": set.NewStringSet("/usr/bin/mawk"),
				"libm.so.6": set.NewStringSet("/usr/bin/mawk", "/usr/bin/abcd"),
			},
			updated: false,
		},
		{
			desc: "merge from nil",
			aMap: nil,
			bMap: StringToStringsMap{
				"libc.so.6": set.NewStringSet("/usr/bin/mawk"),
				"libm.so.6": set.NewStringSet("/usr/bin/mawk", "/usr/bin/abcd"),
			},
			expected: StringToStringsMap{
				"libc.so.6": set.NewStringSet("/usr/bin/mawk"),
				"libm.so.6": set.NewStringSet("/usr/bin/mawk", "/usr/bin/abcd"),
			},
			updated: true,
		},
	}
	for _, c := range testCases {
		t.Run(c.desc, func(t *testing.T) {
			updated := c.aMap.Merge(c.bMap)
			assert.Equal(t, c.expected, c.aMap)
			assert.Equal(t, c.updated, updated)
		})
	}
}
