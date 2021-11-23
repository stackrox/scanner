package database

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"github.com/stackrox/rox/pkg/set"
)

func StringMapArrayString(m map[string][]string) interface {
	driver.Valuer
	sql.Scanner
} {
	return (*DependencyMap)(&m)
}

type DependencyMap map[string][]string

// Value returns the JSON-encoded representation
func (a DependencyMap) Value() (driver.Value, error) {
	return json.Marshal(a)
}

// Scan Decodes a JSON-encoded value
func (a *DependencyMap) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}
	// Unmarshal from json to map[string][]string
	*a = make(map[string][]string)
	if err := json.Unmarshal(b, a); err != nil {
		return err
	}
	return nil
}

func (a DependencyMap) Merge(b DependencyMap) {
	for k, v := range b {
		newValue := set.NewStringSet(a[k]...)
		newValue.AddAll(v...)
		a[k] = newValue.AsSlice()
	}
}