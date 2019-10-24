package psql

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq" // import the postgres implementation
	"github.com/stackrox/scanner/pkg/clairify/db"
	"github.com/stackrox/scanner/pkg/clairify/types"
)

type psql struct {
	*sql.DB
}

func (p *psql) createTable(query string) error {
	_, err := p.Exec(query)
	return err
}

// GetLayerByName fetches the latest layer for an image by the image SHA.
func (p *psql) GetLayerBySHA(sha string) (string, bool, error) {
	rows, err := p.Query("SELECT layer FROM ImageToLayer WHERE sha = $1", sha)
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
func (p *psql) GetLayerByName(name string) (string, bool, error) {
	rows, err := p.Query("SELECT layer FROM ImageToLayer WHERE name = $1", name)
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
func (p *psql) AddImage(layer string, image types.Image) error {
	_, exists, err := p.GetLayerBySHA(image.SHA)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	_, err = p.Exec(`INSERT INTO ImageToLayer(layer, name, sha)
	VALUES ($1, $2, $3); `, layer, image.TaggedName(), image.SHA)
	return err
}

// New returns a new instance of the psql database implementation unless it cannot ping the database.
func New(endpoint, username, password, sslMode string) (db.DB, error) {
	var postgres psql
	var userData string
	if username != "" {
		userData = username
	}
	if password != "" {
		userData += ":" + password
	}
	userData += "@"
	postgresEndpoint := fmt.Sprintf("postgres://%s%s/postgres?sslmode=%s", userData, endpoint, sslMode)
	var err error
	postgres.DB, err = sql.Open("postgres", postgresEndpoint)
	if err != nil {
		return nil, fmt.Errorf("could not open database: %s", err)
	}
	if err := postgres.Ping(); err != nil {
		postgres.Close()
		return nil, err
	}
	return &postgres, nil
}
