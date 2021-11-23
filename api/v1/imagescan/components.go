package imagescan

import (
	modelsV1 "github.com/stackrox/scanner/api/v1"
	"github.com/stackrox/scanner/database"
	v1 "github.com/stackrox/scanner/generated/shared/api/v1"
)

// GetComponentsByLayer reads all the component data from the database and returns it.
func GetComponentsByLayer(db database.Datastore, dbLayer database.Layer, lineage string, opts *database.DatastoreOptions) (*v1.Layers, error) {
	var namespaceName string
	if dbLayer.Namespace != nil {
		namespaceName = dbLayer.Namespace.Name
	}

	notes := modelsV1.GetNotes(namespaceName, opts.GetUncertifiedRHEL())

	if dbLayer.Features != nil {

	}
}
