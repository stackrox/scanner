package database

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"sort"

	"github.com/stackrox/rox/pkg/set"
)

// NewStringToStringsMap creates a NewStringToStringsMap from a string to string set map.
func NewStringToStringsMap(m map[string]set.StringSet) interface {
	driver.Valuer
	sql.Scanner
} {
	return (*StringToStringsMap)(&m)
}

// StringToStringsMap defines driver.Valuer and sql.Scanner for a map from string to set of string
type StringToStringsMap map[string]set.StringSet

type internalMap []internalMapEntry
type internalMapEntry struct {
	K string   `json:"k,omitempty"`
	V []string `json:"v,omitempty"`
}

func (m internalMap) Len() int {
	return len(m)
}

func (m internalMap) Less(i, j int) bool {
	return m[i].K < m[j].K
}

func (m internalMap) Swap(i, j int) {
	m[j], m[i] = m[i], m[j]
}

// Value returns the JSON-encoded representation
func (m StringToStringsMap) Value() (driver.Value, error) {
	converted := make(internalMap, 0, len(m))
	for k, v := range m {
		converted = append(converted, internalMapEntry{
			K: k,
			V: v.AsSortedSlice(func(i, j string) bool { return i < j }),
		})
	}
	sort.Sort(converted)
	return json.Marshal(converted)
}

// Scan Decodes a JSON-encoded value
func (m *StringToStringsMap) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}
	// Unmarshal from json to map[string][]string
	var raw internalMap
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	scanned := make(StringToStringsMap, len(raw))
	for _, r := range raw {
		scanned[r.K] = set.NewStringSet(r.V...)
	}
	*m = scanned
	return nil
}

// Merge merges map b to map a.
// If a contains str_a -> ["a", "b"]
//    b contains str_a -> ["b", "c"]
// Then after merging:
//    a contains str_a -> {"a", "b", "c"}
func (m *StringToStringsMap) Merge(b StringToStringsMap) {
	if len(b) == 0 {
		return
	}
	if *m == nil {
		*m = make(StringToStringsMap)
	}
	for k, v := range b {
		(*m)[k] = (*m)[k].Union(v)
	}
}
