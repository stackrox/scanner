package cache

import (
	"archive/zip"
	"time"
)

type Cache interface {
	Dir() string
	LoadFromDirectory(definitionsDir string) error
	LoadFromZip(zipR *zip.ReadCloser, definitionsDir string) error
	GetLastUpdate() time.Time
	SetLastUpdate(t time.Time)
}
