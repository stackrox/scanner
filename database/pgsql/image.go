package pgsql

import "github.com/stackrox/scanner/database"

// GetLayerBySHA fetches the latest layer for an image by the image SHA.
func (pgSQL *pgSQL) GetLayerBySHA(sha string, opts *database.DatastoreOptions) (string, bool, error) {
	rows, err := pgSQL.Query("SELECT layer FROM ImageToLayer WHERE sha = $1 AND uncertified_rhel = $2", sha, opts.GetUncertifiedRHEL())
	if err != nil {
		return "", false, err
	}
	defer rows.Close()
	for rows.Next() {
		var layer string
		err = rows.Scan(&layer)
		return layer, true, err
	}
	return "", false, nil
}

// GetLayerByName fetches the latest layer for an image by the image name.
func (pgSQL *pgSQL) GetLayerByName(name string, opts *database.DatastoreOptions) (string, bool, error) {
	rows, err := pgSQL.Query("SELECT layer FROM ImageToLayer WHERE name = $1 AND uncertified_rhel = $2", name, opts.GetUncertifiedRHEL())
	if err != nil {
		return "", false, err
	}
	defer rows.Close()
	for rows.Next() {
		var layer string
		err = rows.Scan(&layer)
		return layer, true, err
	}
	return "", false, nil
}

// AddImage inserts an image and its latest layer into the database.
// Duplicate entries are ignored.
func (pgSQL *pgSQL) AddImage(layer string, digest, name string, opts *database.DatastoreOptions) error {
	_, err := pgSQL.Exec(`INSERT INTO ImageToLayer(layer, name, sha, uncertified_rhel)
	VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING;`, layer, name, digest, opts.GetUncertifiedRHEL())
	return err
}
