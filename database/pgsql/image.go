package pgsql

import (
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/database"
)

// GetLayerBySHA fetches the latest layer for an image by the image SHA.
func (pgSQL *pgSQL) GetLayerBySHA(sha string, opts *database.DatastoreOptions) (string, string, bool, error) {
	rows, err := pgSQL.Query("SELECT layer, lineage FROM ImageToLayer WHERE sha = $1 AND uncertified_rhel = $2", sha, opts.GetUncertifiedRHEL())
	if err != nil {
		return "", "", false, err
	}
	defer utils.IgnoreError(rows.Close)
	for rows.Next() {
		var layer, lineage string
		err = rows.Scan(&layer, &lineage)
		return layer, lineage, true, err
	}
	return "", "", false, rows.Err()
}

// GetLayerByName fetches the latest layer for an image by the image name.
func (pgSQL *pgSQL) GetLayerByName(name string, opts *database.DatastoreOptions) (string, string, bool, error) {
	rows, err := pgSQL.Query("SELECT layer,lineage FROM ImageToLayer WHERE name = $1 AND uncertified_rhel = $2", name, opts.GetUncertifiedRHEL())
	if err != nil {
		return "", "", false, err
	}
	defer utils.IgnoreError(rows.Close)
	for rows.Next() {
		var layer, lineage string
		err = rows.Scan(&layer, &lineage)
		return layer, lineage, true, err
	}
	return "", "", false, rows.Err()
}

// AddImage inserts an image and its latest layer into the database.
// Duplicate entries are ignored.
func (pgSQL *pgSQL) AddImage(layer, digest, lineage, name string, opts *database.DatastoreOptions) error {
	_, err := pgSQL.Exec(`INSERT INTO ImageToLayer(layer, name, lineage, sha, uncertified_rhel)
	VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING;`, layer, name, lineage, digest, opts.GetUncertifiedRHEL())
	return err
}
