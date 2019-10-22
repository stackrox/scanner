package db

import "github.com/stackrox/scanner/pkg/clairify/types"

// DB is the interface that all DB implementations must satisfy.
type DB interface {
	GetLayerBySHA(sha string) (string, bool, error)
	GetLayerByName(name string) (string, bool, error)
	AddImage(layer string, image types.Image) error
}
