package pgsql

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
)

func StringMapArrayString(m map[string][]string) interface {
	driver.Valuer
	sql.Scanner
} {
	return (* stringMapArrayString)(&m)
}

type stringMapArrayString map[string][]string

// Value returns the JSON-encoded representation
func (a stringMapArrayString) Value() (driver.Value, error) {
	return json.Marshal(a)
}

// Scan Decodes a JSON-encoded value
func (a *stringMapArrayString) Scan(value interface{}) error {
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