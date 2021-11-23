package database

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"github.com/stackrox/rox/pkg/set"
)

func NewStringToStringsMap(m map[string]set.StringSet) interface {
	driver.Valuer
	sql.Scanner
} {
	return (*StringToStringsMap)(&m)
}

type StringToStringsMap map[string]set.StringSet

// Value returns the JSON-encoded representation
func (m StringToStringsMap) Value() (driver.Value, error) {
	converted := make(map[string][]string, len(m))
	for k, v := range m {
		converted[k] = v.AsSlice()
	}
	return json.Marshal(converted)
}

// Scan Decodes a JSON-encoded value
func (m *StringToStringsMap) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}
	// Unmarshal from json to map[string][]string
	raw := make(map[string][]string)
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	for k, v := range raw {
		(*m)[k] = set.NewStringSet(v...)
	}
	return nil
}

// Merge merges map b to map a.
// If a contains str_a -> ["a", "b"]
//    b contains str_a -> ["b", "c"]
// Then after merging:
//    a contains str_a -> {"a", "b", "c"}
func (m StringToStringsMap) Merge(b StringToStringsMap) {
	for k, v := range b {
		m[k] = m[k].Union(v)
	}
}