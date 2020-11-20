package cache

import (
	"time"
)

type Cache interface {
	Dir() string
	LoadFromDirectory(definitionsDir string) error
	GetLastUpdate() time.Time
	SetLastUpdate(t time.Time)
}
