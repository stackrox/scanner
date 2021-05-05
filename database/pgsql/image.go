package pgsql

// GetLayerBySHA fetches the latest layer for an image by the image SHA.
func (pgSQL *pgSQL) GetLayerBySHA(sha string, uncertifiedRHEL bool) (string, bool, error) {
	rows, err := pgSQL.Query("SELECT layer FROM ImageToLayer WHERE sha = $1 AND uncertified_rhel = $2", sha, uncertifiedRHEL)
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
func (pgSQL *pgSQL) GetLayerByName(name string, uncertifiedRHEL bool) (string, bool, error) {
	rows, err := pgSQL.Query("SELECT layer FROM ImageToLayer WHERE name = $1 AND uncertified_rhel = $2", name, uncertifiedRHEL)
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
func (pgSQL *pgSQL) AddImage(layer string, digest, name string, uncertifiedRHEL bool) error {
	_, err := pgSQL.Exec(`INSERT INTO ImageToLayer(layer, name, sha, uncertified_rhel)
	VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING;`, layer, name, digest, uncertifiedRHEL)
	return err
}
