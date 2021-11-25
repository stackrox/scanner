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