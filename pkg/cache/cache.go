package cache

import (
	"time"
)

// Cache is the interface for common cache operations.
type Cache interface {
	Dir() string
	LoadFromDirectory(definitionsDir string) error
	GetLastUpdate() time.Time
	SetLastUpdate(t time.Time)
}
