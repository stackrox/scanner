// This code is adapted from https://github.com/boltdb/bolt/blob/master/cmd/bolt/main.go
// which is licensed under the MIT License

package bolthelper

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	bolt "go.etcd.io/bbolt"
)

const (
	dbOpenTimeout = 2 * time.Minute
)

// New returns an instance of the persistent BoltDB store
func New(path string) (*bolt.DB, error) {
	dirPath := filepath.Dir(path)
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		err = os.MkdirAll(dirPath, 0700)
		if err != nil {
			return nil, errors.Wrapf(err, "Error creating db path %v", dirPath)
		}
	} else if err != nil {
		return nil, err
	}
	options := *bolt.DefaultOptions
	options.FreelistType = bolt.FreelistMapType
	options.Timeout = dbOpenTimeout
	db, err := bolt.Open(path, 0600, &options)
	if err != nil {
		return nil, err
	}

	return db, nil
}

// NewTemp creates a new DB, but places it in the host temporary directory.
func NewTemp(dbPath string) (*bolt.DB, error) {
	tmpDir, err := os.MkdirTemp("", "")
	if err != nil {
		return nil, err
	}
	return New(filepath.Join(tmpDir, strings.ReplaceAll(dbPath, "/", "_")))
}
