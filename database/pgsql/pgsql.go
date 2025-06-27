// Copyright 2017 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package pgsql implements database.Datastore with PostgreSQL.
package pgsql

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/lib/pq"
	"github.com/pkg/errors"
	"github.com/remind101/migrate"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/database/metrics"
	"github.com/stackrox/scanner/database/pgsql/migrations"
	"github.com/stackrox/scanner/pkg/commonerr"
	"go.yaml.in/yaml/v3"
)

const (
	passwordFile = "/run/secrets/stackrox.io/secrets/password"
)

func init() {
	database.Register("pgsql", openDatabase)
}

// Queryer defines an entity which performs queries (like the pgSQL struct).
type Queryer interface {
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
}

type pgSQL struct {
	*sql.DB
	config Config
}

// Close closes the database and destroys if ManageDatabaseLifecycle has been specified in
// the configuration.
func (pgSQL *pgSQL) Close() {
	if pgSQL.DB != nil {
		pgSQL.DB.Close()
	}

	if pgSQL.config.ManageDatabaseLifecycle {
		dbName, pgSourceURL, _ := parseConnectionString(pgSQL.config.Source)
		dropDatabase(pgSourceURL, dbName)
	}
}

// Ping verifies that the database is accessible.
func (pgSQL *pgSQL) Ping() bool {
	return pgSQL.DB.Ping() == nil
}

// Config is the configuration that is used by openDatabase.
type Config struct {
	Source                string
	CacheSize             int
	ConnectionMaxLifetime *time.Duration

	ManageDatabaseLifecycle bool
	FixturePath             string
}

// openDatabase opens a PostgresSQL-backed Datastore using the given
// configuration.
//
// It immediately runs all necessary migrations. If ManageDatabaseLifecycle is
// specified, the database will be created first. If FixturePath is specified,
// every SQL queries that are present insides will be executed.
func openDatabase(registrableComponentConfig database.RegistrableComponentConfig, passwordRequired bool) (database.Datastore, error) {
	var pg pgSQL
	var err error

	// Parse configuration.
	pg.config = Config{
		CacheSize: 16384,
	}
	bytes, err := yaml.Marshal(registrableComponentConfig.Options)
	if err != nil {
		return nil, fmt.Errorf("pgsql: could not load configuration: %v", err)
	}
	err = yaml.Unmarshal(bytes, &pg.config)
	if err != nil {
		return nil, fmt.Errorf("pgsql: could not load configuration: %v", err)
	}

	dbName, pgSourceURL, err := parseConnectionString(pg.config.Source)
	if err != nil {
		return nil, err
	}

	src := pg.config.Source
	if passwordRequired {
		if _, err := os.Stat(passwordFile); err == nil {
			password, err := os.ReadFile(passwordFile)
			if err != nil {
				return nil, errors.Wrapf(err, "pgsql: could not load password file %q", passwordFile)
			}
			src = fmt.Sprintf("%s password=%s", pg.config.Source, password)
		} else if !os.IsNotExist(err) {
			return nil, errors.Wrapf(err, "pgsql: could not stat password file %q", passwordFile)
		} else {
			return nil, errors.Errorf("pgsql: no password file at expected location %q", passwordFile)
		}
	}

	// Create database.
	if pg.config.ManageDatabaseLifecycle {
		log.Info("pgsql: creating database")
		if err = createDatabase(pgSourceURL, dbName); err != nil {
			return nil, err
		}
	}

	// Open database.
	pg.DB, err = sql.Open("postgres", src)
	if err != nil {
		pg.Close()
		return nil, fmt.Errorf("pgsql: could not open database: %v", err)
	}
	if pg.config.ConnectionMaxLifetime != nil {
		pg.DB.SetConnMaxLifetime(*pg.config.ConnectionMaxLifetime)
	}

	// Verify database state.
	if err = pg.DB.Ping(); err != nil {
		pg.Close()
		return nil, fmt.Errorf("pgsql: could not open database: %v", err)
	}

	// Run migrations.
	if err = migrateDatabase(pg.DB); err != nil {
		pg.Close()
		return nil, err
	}

	// Load fixture data.
	if pg.config.FixturePath != "" {
		log.Info("pgsql: loading fixtures")

		d, err := os.ReadFile(pg.config.FixturePath)
		if err != nil {
			pg.Close()
			return nil, fmt.Errorf("pgsql: could not open fixture file: %v", err)
		}

		_, err = pg.DB.Exec(string(d))
		if err != nil {
			pg.Close()
			return nil, fmt.Errorf("pgsql: an error occured while importing fixtures: %v", err)
		}
	}

	return &pg, nil
}

func parseConnectionString(source string) (dbName string, pgSourceURL string, err error) {
	if source == "" {
		return "", "", commonerr.NewBadRequestError("pgsql: no database connection string specified")
	}

	sourceURL, err := url.Parse(source)
	if err != nil {
		return "", "", commonerr.NewBadRequestError("pgsql: database connection string is not a valid URL")
	}

	dbName = strings.TrimPrefix(sourceURL.Path, "/")

	pgSource := *sourceURL
	pgSource.Path = "/postgres"
	pgSourceURL = pgSource.String()

	return
}

// migrate runs all available migrations on a pgSQL database.
func migrateDatabase(db *sql.DB) error {
	log.Info("running database migrations")

	err := migrate.NewPostgresMigrator(db).Exec(migrate.Up, migrations.Migrations...)
	if err != nil {
		return fmt.Errorf("pgsql: an error occured while running migrations: %v", err)
	}

	log.Info("database migration ran successfully")
	return nil
}

// createDatabase creates a new database.
// The source parameter should not contain a dbname.
func createDatabase(source, dbName string) error {
	// Open database.
	db, err := sql.Open("postgres", source)
	if err != nil {
		return fmt.Errorf("pgsql: could not open 'postgres' database for creation: %v", err)
	}
	defer db.Close()

	// Create database.
	_, err = db.Exec("CREATE DATABASE " + dbName)
	if err != nil {
		return fmt.Errorf("pgsql: could not create database: %v", err)
	}

	return nil
}

// dropDatabase drops an existing database.
// The source parameter should not contain a dbname.
func dropDatabase(source, dbName string) error {
	// Open database.
	db, err := sql.Open("postgres", source)
	if err != nil {
		return fmt.Errorf("could not open database (DropDatabase): %v", err)
	}
	defer db.Close()

	// Kill any opened connection.
	if _, err = db.Exec(`
    SELECT pg_terminate_backend(pg_stat_activity.pid)
    FROM pg_stat_activity
    WHERE pg_stat_activity.datname = $1
    AND pid <> pg_backend_pid()`, dbName); err != nil {
		return fmt.Errorf("could not drop database: %v", err)
	}

	// Drop database.
	if _, err = db.Exec("DROP DATABASE " + dbName); err != nil {
		return fmt.Errorf("could not drop database: %v", err)
	}

	return nil
}

// handleError logs an error with an extra description and masks the error if it's an SQL one.
// This ensures we never return plain SQL errors and leak anything.
func handleError(desc string, err error) error {
	if err == nil {
		return nil
	}

	if err == sql.ErrNoRows {
		return commonerr.ErrNotFound
	}

	log.WithError(err).WithField("Description", desc).Error("Handled Database Error")
	metrics.IncErrors(desc)

	if _, o := err.(*pq.Error); o || err == sql.ErrTxDone || strings.HasPrefix(err.Error(), "sql:") {
		return database.ErrBackendException
	}

	return err
}
