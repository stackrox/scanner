package server

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	v1 "github.com/stackrox/scanner/api/v1"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/clairify/types"
	"github.com/stackrox/scanner/pkg/commonerr"
	"github.com/stackrox/scanner/pkg/mtls"
	server "github.com/stackrox/scanner/pkg/scan"
)

// Server is the HTTP server for Clairify.
type Server struct {
	registryCreator         types.RegistryClientCreator
	insecureRegistryCreator types.RegistryClientCreator
	endpoint                string
	storage                 database.Datastore
	httpServer              *http.Server
}

// New returns a new instantiation of the Server.
func New(serverEndpoint string, db database.Datastore, creator, insecureCreator types.RegistryClientCreator) *Server {
	return &Server{
		registryCreator:         creator,
		insecureRegistryCreator: insecureCreator,
		endpoint:                serverEndpoint,
		storage:                 db,
	}
}

func clairErrorString(w http.ResponseWriter, status int, template string, args ...interface{}) {
	msg := fmt.Sprintf(template, args...)
	logrus.Debugf("error %s with status code %d", msg, status)
	envelope := v1.LayerEnvelope{
		Error: &v1.Error{
			Message: msg,
		},
	}
	bytes, _ := json.Marshal(envelope)
	w.WriteHeader(status)
	w.Write(bytes)
}

func clairError(w http.ResponseWriter, status int, err error) {
	clairErrorString(w, status, err.Error())
}

func (s *Server) getClairLayer(w http.ResponseWriter, r *http.Request, layerName string) {
	dbLayer, err := s.storage.FindLayer(layerName, true, true)
	if err == commonerr.ErrNotFound {
		clairErrorString(w, http.StatusNotFound, "Could not find Clair layer %q", layerName)
		return
	} else if err != nil {
		clairError(w, http.StatusInternalServerError, err)
		return
	}

	layer, err := v1.LayerFromDatabaseModel(s.storage, dbLayer, true, true)
	if err != nil {
		clairError(w, http.StatusInternalServerError, err)
		return
	}
	env := &v1.LayerEnvelope{
		Layer: &layer,
	}

	bytes, err := json.Marshal(env)
	if err != nil {
		clairError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(bytes)
}

// GetResultsBySHA implements retrieving scan data via image SHA.
func (s *Server) GetResultsBySHA(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sha, ok := vars[`sha`]
	if !ok {
		clairErrorString(w, http.StatusBadRequest, "sha must be provided")
		return
	}
	layer, exists, err := s.storage.GetLayerBySHA(sha)
	if err != nil {
		clairError(w, http.StatusInternalServerError, err)
		return
	}
	if !exists {
		clairErrorString(w, http.StatusNotFound, "Could not find sha %q", sha)
		return
	}
	s.getClairLayer(w, r, layer)
}

// GetResultsByImage implements retrieving scan data via image name.
func (s *Server) GetResultsByImage(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	var remote string
	var ok bool
	remote, ok = vars[`remote`]
	if !ok {
		namespace, ok := vars[`namespace`]
		if !ok {
			clairErrorString(w, http.StatusBadRequest, "image remote or both namespace and repo must be provided")
			return
		}
		repo, ok := vars[`repo`]
		if !ok {
			clairErrorString(w, http.StatusBadRequest, "image remote or both namespace and repo must be provided")
			return
		}
		remote = fmt.Sprintf("%s/%s", namespace, repo)
	}

	registry, ok := vars[`registry`]
	if !ok {
		clairErrorString(w, http.StatusBadRequest, "image registry must be provided")
		return
	}

	tag, ok := vars[`tag`]
	if !ok {
		clairErrorString(w, http.StatusBadRequest, "image tag must be provided")
		return
	}
	image := fmt.Sprintf("%s/%s:%s", registry, remote, tag)
	logrus.Debugf("Getting layer sha by name %s", image)
	layer, exists, err := s.storage.GetLayerByName(image)
	if err != nil {
		clairError(w, http.StatusInternalServerError, err)
		return
	}
	if !exists {
		clairErrorString(w, http.StatusNotFound, "Could not find image %q", image)
		return
	}
	s.getClairLayer(w, r, layer)
}

func getAuth(authHeader string) (string, string, error) {
	// If no auth was passed, we'll assume it isn't necessary.
	if authHeader == "" {
		return "", "", nil
	}
	if !strings.HasPrefix(authHeader, "Basic ") {
		return "", "", errors.New("only basic auth is currently supported")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, "Basic "))
	if err != nil {
		return "", "", err
	}
	spl := strings.SplitN(string(decoded), ":", 2)
	if len(spl) != 2 {
		return "", "", fmt.Errorf("malformed basic auth")
	}
	return strings.TrimSpace(spl[0]), strings.TrimSpace(spl[1]), nil
}

// ScanImage implements pushing an image's layers to Clair.
func (s *Server) ScanImage(w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		clairError(w, http.StatusInternalServerError, err)
		return
	}

	var imageRequest types.ImageRequest
	if err := json.Unmarshal(data, &imageRequest); err != nil {
		clairError(w, http.StatusBadRequest, err)
		return
	}

	username, password, err := getAuth(r.Header.Get("Authorization"))
	if err != nil {
		clairError(w, http.StatusBadRequest, err)
		return
	}

	logrus.Infof("PROCESSING IMAGE FROM STRING: %+v", imageRequest)
	image, err := types.GenerateImageFromString(imageRequest.Image)
	if err != nil {
		clairError(w, http.StatusBadRequest, err)
		return
	}

	_, err = server.ProcessImage(s.storage, image, imageRequest.Registry, username, password, imageRequest.Insecure)
	if err != nil {
		clairErrorString(w, http.StatusInternalServerError, "error processing image %q: %v", imageRequest.Image, err)
		return
	}
	imageEnvelope := types.ImageEnvelope{
		Image: image,
	}
	data, err = json.Marshal(imageEnvelope)
	if err != nil {
		clairError(w, http.StatusInternalServerError, err)
		return
	}
	w.Write(data)
}

// Ping implements a simple handler for verifying that Clairify is up.
func (s *Server) Ping(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("{}"))
}

// Start starts the server listening.
func (s *Server) Start() error {
	r := mux.NewRouter()

	apiRoots := []string{"clairify", "scanner"}

	for _, root := range apiRoots {
		r.HandleFunc(fmt.Sprintf("/%s/ping", root), s.Ping).Methods("GET")
		r.HandleFunc(fmt.Sprintf("/%s/image", root), s.ScanImage).Methods("POST")

		r.HandleFunc(fmt.Sprintf("/%s/sha/{sha}", root), s.GetResultsBySHA).Methods("GET")
		r.HandleFunc(fmt.Sprintf("/%s/image/{registry}/{remote}/{tag}", root), s.GetResultsByImage).Methods("GET")
		r.HandleFunc(fmt.Sprintf("/%s/image/{registry}/{namespace}/{repo}/{tag}", root), s.GetResultsByImage).Methods("GET")
	}

	var tlsConfig *tls.Config
	var listener net.Listener
	var err error

	tlsConfig, err = mtls.TLSServerConfig()
	if err != nil {
		return err
	}
	tlsConfig.NextProtos = nil

	listener, err = tls.Listen("tcp", s.endpoint, tlsConfig)
	if err != nil {
		return err
	}
	addr := listener.Addr().String()

	srv := &http.Server{
		Handler:      r,
		Addr:         addr,
		WriteTimeout: 5 * time.Minute,
		ReadTimeout:  15 * time.Second,
		TLSConfig:    tlsConfig,
	}
	s.httpServer = srv
	logrus.Infof("Listening on %s", s.endpoint)
	if listener != nil {
		return srv.Serve(listener)
	}
	return srv.ListenAndServe()
}

// Close closes the server's connections
func (s *Server) Close() {
	s.httpServer.Close()
}
