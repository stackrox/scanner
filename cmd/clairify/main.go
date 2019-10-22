package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/pkg/clairify/clair"
	"github.com/stackrox/scanner/pkg/clairify/db"
	"github.com/stackrox/scanner/pkg/clairify/db/psql"
	"github.com/stackrox/scanner/pkg/clairify/server"
	"github.com/stackrox/scanner/pkg/clairify/types"
)

const (
	clairEndpoint = "http://127.0.0.1:6060"

	pgEndpoint = "127.0.0.1"
	pgUser     = "postgres"
	pgSSLMode  = "disable"
)

func main() {
	var (
		port int
	)
	flag.IntVar(&port, "port", 8080, "Port for Clairify to listen on")
	flag.Parse()

	client := clair.NewClient(clairEndpoint)

	var err error
	var database db.DB

	// Let Postgres start
	for i := 0; i < 5; i++ {
		database, err = psql.New(pgEndpoint, pgUser, "", pgSSLMode)
		if err == nil {
			break
		}
		logrus.Errorf("Error accessing Postgres: %s", err)
		time.Sleep(10 * time.Second)
	}
	if err != nil {
		log.Fatal(err)
	}

	listenAddr := fmt.Sprintf(":%d", port)
	serv := server.New(listenAddr, client, database, types.DockerRegistryCreator, types.InsecureDockerRegistryCreator)
	if err := serv.Start(); err != nil {
		log.Fatal(err)
	}
}
