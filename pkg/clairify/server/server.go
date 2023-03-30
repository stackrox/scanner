package server

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	protoTypes "github.com/gogo/protobuf/types"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	v1 "github.com/stackrox/scanner/api/v1"
	v1common "github.com/stackrox/scanner/api/v1/common"
	"github.com/stackrox/scanner/database"
	protoV1 "github.com/stackrox/scanner/generated/scanner/api/v1"
	"github.com/stackrox/scanner/pkg/clairify/server/middleware"
	"github.com/stackrox/scanner/pkg/clairify/types"
	"github.com/stackrox/scanner/pkg/commonerr"
	"github.com/stackrox/scanner/pkg/mtls"
	server "github.com/stackrox/scanner/pkg/scan"
	"github.com/stackrox/scanner/pkg/updater"
	"github.com/stackrox/scanner/pkg/version"
)

// Server is the HTTP server for Clairify.
type Server struct {
	version    string
	endpoint   string
	storage    database.Datastore
	httpServer *http.Server
}

// New returns a new instantiation of the Server.
func New(serverEndpoint string, db database.Datastore) *Server {
	return &Server{
		version:  version.Version,
		endpoint: serverEndpoint,
		storage:  db,
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

func (s *Server) getClairLayer(w http.ResponseWriter, layerName, lineage string, uncertifiedRHEL bool) {
	opts := &database.DatastoreOptions{
		WithVulnerabilities: true,
		WithFeatures:        true,
		UncertifiedRHEL:     uncertifiedRHEL,
	}

	dbLayer, err := s.storage.FindLayer(layerName, lineage, opts)
	if err == commonerr.ErrNotFound {
		clairErrorString(w, http.StatusNotFound, "Could not find Clair layer %q", layerName)
		return
	} else if err != nil {
		clairError(w, http.StatusInternalServerError, err)
		return
	}
	depMap := v1common.GetDepMap(dbLayer.Features)

	layer, notes, err := v1.LayerFromDatabaseModel(s.storage, dbLayer, lineage, depMap, opts)
	if err != nil {
		clairError(w, http.StatusInternalServerError, err)
		return
	}
	env := &v1.LayerEnvelope{
		ScannerVersion: s.version,
		Layer:          &layer,
		Notes:          notes,
	}

	bytes, err := json.Marshal(env)
	if err != nil {
		clairError(w, http.StatusInternalServerError, err)
		return
	}
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
	uncertifiedRHEL := getUncertifiedRHELResults(r.URL.Query())
	layer, lineage, exists, err := s.storage.GetLayerBySHA(sha, &database.DatastoreOptions{
		UncertifiedRHEL: uncertifiedRHEL,
	})
	if err != nil {
		clairError(w, http.StatusInternalServerError, err)
		return
	}
	if !exists {
		clairErrorString(w, http.StatusNotFound, "Could not find sha %q", sha)
		return
	}
	s.getClairLayer(w, layer, lineage, uncertifiedRHEL)
}

func parseImagePath(path string) (string, error) {
	image := strings.TrimPrefix(path, "/scanner/image/")
	image = strings.TrimPrefix(image, "/clairify/image/")

	// last value needs to be tag
	tagIdx := strings.LastIndex(image, "/")
	if tagIdx == -1 {
		return "", errors.Errorf("invalid image format: %q", image)
	}
	basePath := image[:tagIdx]
	tag := image[tagIdx+1:]
	if tag == "" {
		return "", errors.Errorf("invalid image format: %q. Tag is required", image)
	}
	return fmt.Sprintf("%s:%s", basePath, tag), nil
}

// GetResultsByImage implements retrieving scan data via image name.
func (s *Server) GetResultsByImage(w http.ResponseWriter, r *http.Request) {
	image, err := parseImagePath(r.URL.Path)
	if err != nil {
		clairErrorString(w, http.StatusBadRequest, err.Error())
		return
	}
	uncertifiedRHEL := getUncertifiedRHELResults(r.URL.Query())
	logrus.Debugf("Getting layer sha by name %s", image)
	layer, lineage, exists, err := s.storage.GetLayerByName(image, &database.DatastoreOptions{
		UncertifiedRHEL: uncertifiedRHEL,
	})
	if err != nil {
		clairError(w, http.StatusInternalServerError, err)
		return
	}
	if !exists {
		clairErrorString(w, http.StatusNotFound, "Could not find image %q", image)
		return
	}
	s.getClairLayer(w, layer, lineage, uncertifiedRHEL)
}

func getUncertifiedRHELResults(queryValues url.Values) bool {
	values := queryValues[types.UncertifiedRHELResultsKey]
	return len(values) == 1 && strings.EqualFold(values[0], "true")
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
		return "", "", errors.New("malformed basic auth")
	}
	return strings.TrimSpace(spl[0]), strings.TrimSpace(spl[1]), nil
}

// ScanImage implements pushing an image's layers to Clair.
func (s *Server) ScanImage(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(r.Body)
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
		clairError(w, http.StatusUnauthorized, err)
		return
	}

	image, err := types.GenerateImageFromString(imageRequest.Image)
	if err != nil {
		clairError(w, http.StatusBadRequest, err)
		return
	}

	logrus.Infof("Start processing image %v", image)
	_, err = server.ProcessImage(s.storage, image, imageRequest.Registry, username, password, imageRequest.Insecure, imageRequest.UncertifiedRHELScan)
	if err != nil {
		logrus.Infof("End processing image %v: failure", image)
		clairErrorString(w, http.StatusInternalServerError, "error processing image %q: %v", imageRequest.Image, err)
		return
	}
	logrus.Infof("End processing image %v: success", image)
	imageEnvelope := types.ImageEnvelope{
		ScannerVersion: s.version,
		Image:          image,
	}
	data, err = json.Marshal(imageEnvelope)
	if err != nil {
		clairError(w, http.StatusInternalServerError, err)
		return
	}
	w.Write(data)
}

// Ping implements a simple handler for verifying that Clairify is up.
func (s *Server) Ping(w http.ResponseWriter, _ *http.Request) {
	pong := types.Pong{
		ScannerVersion: s.version,
		Status:         "OK",
	}
	data, err := json.Marshal(pong)
	if err != nil {
		// Return an error to the user.
		// Yes, the Scanner is up, but there is a serious problem if we cannot marshal the simple Pong message.
		clairErrorString(w, http.StatusInternalServerError, "cannot determine scanner version")
		return
	}
	w.Write(data)
}

// GetVulnDefsMetadata returns vulnerability definitions information.
func (s *Server) GetVulnDefsMetadata(w http.ResponseWriter, _ *http.Request) {
	t, err := updater.GetLastUpdatedTime(s.storage)
	if err != nil {
		clairErrorString(w, http.StatusInternalServerError, "failed to obtain vulnerability definitions update timestamp: %v", err)
		return
	}

	ts, err := protoTypes.TimestampProto(t)
	if err != nil {
		clairErrorString(w, http.StatusInternalServerError, "failed to obtain vulnerability definitions update timestamp: %v", err)
		return
	}

	vulnDefsInfo := &protoV1.VulnDefsMetadata{
		LastUpdatedTime: ts,
	}

	data, err := json.Marshal(vulnDefsInfo)
	if err != nil {
		clairError(w, http.StatusInternalServerError, err)
		return
	}
	w.Write(data)
}

// Start starts the server listening.
func (s *Server) Start() error {
	r := mux.NewRouter()
	// Middlewares are executed in order.
	r.Use(
		middleware.Log(),
		// Ensure the user is authorized before doing anything other than logging.
		middleware.VerifyPeerCerts(),
		middleware.SlimMode(),
	)

	apiRoots := []string{"clairify", "scanner"}

	for _, root := range apiRoots {
		r.HandleFunc(fmt.Sprintf("/%s/ping", root), s.Ping).Methods(http.MethodGet)

		r.HandleFunc(fmt.Sprintf("/%s/sha/{sha}", root), s.GetResultsBySHA).Methods(http.MethodGet)
		r.HandleFunc(fmt.Sprintf("/%s/image", root), s.ScanImage).Methods(http.MethodPost)
		r.PathPrefix(fmt.Sprintf("/%s/image/", root)).HandlerFunc(s.GetResultsByImage).Methods(http.MethodGet)

		r.HandleFunc(fmt.Sprintf("/%s/vulndefs/metadata", root), s.GetVulnDefsMetadata).Methods(http.MethodGet)
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
	return srv.Serve(listener)
}

// Close closes the server's connections
func (s *Server) Close() {
	if err := s.httpServer.Shutdown(context.Background()); err != nil {
		logrus.Error(err)
	}
}
