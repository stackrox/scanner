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
	"github.com/stackrox/rox/pkg/httputil"
	v1 "github.com/stackrox/scanner/api/v1"
	"github.com/stackrox/scanner/database"
	protoV1 "github.com/stackrox/scanner/generated/shared/api/v1"
	"github.com/stackrox/scanner/pkg/clairify/types"
	"github.com/stackrox/scanner/pkg/commonerr"
	"github.com/stackrox/scanner/pkg/env"
	"github.com/stackrox/scanner/pkg/mtls"
	server "github.com/stackrox/scanner/pkg/scan"
	"github.com/stackrox/scanner/pkg/updater"
	"google.golang.org/grpc/codes"
)

var (
	skipPeerValidation = env.SkipPeerValidation.Enabled()
)

// Server is the HTTP server for Clairify.
type Server struct {
	endpoint   string
	storage    database.Datastore
	httpServer *http.Server
}

// New returns a new instantiation of the Server.
func New(serverEndpoint string, db database.Datastore) *Server {
	return &Server{
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

func (s *Server) getClairLayer(w http.ResponseWriter, layerName string, getUncertifiedRHEL bool) {
	dbLayer, err := s.storage.FindLayer(layerName, true, true)
	if err == commonerr.ErrNotFound {
		clairErrorString(w, http.StatusNotFound, "Could not find Clair layer %q", layerName)
		return
	} else if err != nil {
		clairError(w, http.StatusInternalServerError, err)
		return
	}

	layer, notes, err := v1.LayerFromDatabaseModel(s.storage, dbLayer, true, true, getUncertifiedRHEL)
	if err != nil {
		clairError(w, http.StatusInternalServerError, err)
		return
	}
	env := &v1.LayerEnvelope{
		Layer: &layer,
		Notes: notes,
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
	layer, exists, err := s.storage.GetLayerBySHA(sha)
	if err != nil {
		clairError(w, http.StatusInternalServerError, err)
		return
	}
	if !exists {
		clairErrorString(w, http.StatusNotFound, "Could not find sha %q", sha)
		return
	}

	s.getClairLayer(w, layer, getUncertifiedRHELResults(r.URL.Query()))
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

	s.getClairLayer(w, layer, getUncertifiedRHELResults(r.URL.Query()))
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

	_, err = server.ProcessImage(s.storage, image, imageRequest.Registry, username, password, imageRequest.Insecure, imageRequest.UncertifiedRHELScan)
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
func (s *Server) Ping(w http.ResponseWriter, _ *http.Request) {
	w.Write([]byte("{}"))
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

func (s *Server) wrapHandlerToVerifyPeerCertificates(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !skipPeerValidation {
			if err := mtls.VerifyCentralPeerCertificate(r); err != nil {
				httputil.WriteGRPCStyleError(w, codes.InvalidArgument, err)
				return
			}
		}
		f(w, r)
	}
}

func (s *Server) handleFuncRouterAndVerifyClient(r *mux.Router, path string, handlerFunc http.HandlerFunc, method string) {
	r.HandleFunc(path, s.wrapHandlerToVerifyPeerCertificates(handlerFunc)).Methods(method)
}

// Start starts the server listening.
func (s *Server) Start() error {
	r := mux.NewRouter()

	apiRoots := []string{"clairify", "scanner"}

	for _, root := range apiRoots {
		// Do not verify client cert for ping endpoint. This will be used by the readiness probe
		r.HandleFunc(fmt.Sprintf("/%s/ping", root), s.Ping).Methods(http.MethodGet)

		s.handleFuncRouterAndVerifyClient(r, fmt.Sprintf("/%s/sha/{sha}", root), s.GetResultsBySHA, http.MethodGet)
		s.handleFuncRouterAndVerifyClient(r, fmt.Sprintf("/%s/image", root), s.ScanImage, http.MethodPost)
		s.handleFuncRouterAndVerifyClient(r, fmt.Sprintf("/%s/vulndefs/metadata", root), s.GetVulnDefsMetadata, http.MethodGet)

		r.PathPrefix(fmt.Sprintf("/%s/image/", root)).HandlerFunc(s.wrapHandlerToVerifyPeerCertificates(s.GetResultsByImage)).Methods(http.MethodGet)
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
