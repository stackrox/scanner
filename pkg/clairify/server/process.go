package server

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/docker/distribution/manifest/schema1"
	"github.com/docker/distribution/manifest/schema2"
	"github.com/heroku/docker-registry-client/registry"
	"github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/pkg/clairify/types"
)

const (
	emptyLayer = "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
)

type authHeader struct {
	Method  string
	Headers map[string]string
}

func getAuthHeaders(method, prefix, auth string) authHeader {
	return authHeader{
		Method: method,
		Headers: map[string]string{
			"Authorization": fmt.Sprintf("%s %s", prefix, auth),
		},
	}
}

func (s *Server) process(image *types.Image, reg types.Registry) (string, string, error) {
	logrus.Debugf("Processing image %s", image)
	sha, layers, err := s.fetchLayers(reg, image)
	if err != nil {
		return sha, "", err
	}
	if len(layers) == 0 {
		return sha, "", fmt.Errorf("No layers to process for image %s", image.String())
	}

	// Token based
	var possibleAuthorizationHeaders = []authHeader{
		getAuthHeaders("Token Auth", "Bearer", reg.GetToken()),
	}
	// Basic Auth
	b64String := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", reg.GetUsername(), reg.GetPassword())))
	possibleAuthorizationHeaders = append(possibleAuthorizationHeaders, getAuthHeaders("Basic Auth", "Basic", b64String))

	// No Auth
	possibleAuthorizationHeaders = append(possibleAuthorizationHeaders, authHeader{Method: "No Auth"})
	// Bearer where the password is a token
	possibleAuthorizationHeaders = append(possibleAuthorizationHeaders, getAuthHeaders("Password as Token", "Bearer", reg.GetPassword()))

	logrus.Infof("Found %v layers for image %v", len(layers), image)
	for _, authHeader := range possibleAuthorizationHeaders {
		if err = s.cc.AnalyzeImage(reg.GetURL(), image, layers, authHeader.Headers); err != nil {
			logrus.Warnf("Failed to analyze image %q with method %q", image.String(), authHeader.Method)
			continue
		}
		break
	}
	return sha, layers[len(layers)-1], err
}

func isEmptyLayer(layer string) bool {
	return layer == emptyLayer
}

func (s *Server) parseV1Layers(manifest *schema1.SignedManifest) []string {
	var layers []string
	// FSLayers has the most recent layer first, append them so that parent layers are first in the slice
	for i := len(manifest.FSLayers) - 1; i >= 0; i-- {
		layer := manifest.FSLayers[i]
		if isEmptyLayer(layer.BlobSum.String()) {
			continue
		}
		layers = append(layers, layer.BlobSum.String())
	}
	return layers
}

func (s *Server) parseV2Layers(manifest *schema2.DeserializedManifest) []string {
	var layers []string
	for _, layer := range manifest.Layers {
		if isEmptyLayer(layer.Digest.String()) {
			continue
		}
		layers = append(layers, layer.Digest.String())
	}
	return layers
}

func (s *Server) handleManifest(reg types.Registry, manifestType string, remote, ref string) ([]string, error) {
	switch manifestType {
	case schema1.MediaTypeManifest:
		manifest, err := reg.Manifest(remote, ref)
		if err != nil {
			return nil, err
		}
		layers := s.parseV1Layers(manifest)
		return layers, nil
	case schema1.MediaTypeSignedManifest:
		manifest, err := reg.SignedManifest(remote, ref)
		if err != nil {
			return nil, err
		}
		layers := s.parseV1Layers(manifest)
		return layers, nil
	case schema2.MediaTypeManifest:
		manifest, err := reg.ManifestV2(remote, ref)
		if err != nil {
			return nil, err
		}
		layers := s.parseV2Layers(manifest)
		return layers, nil

	case registry.MediaTypeManifestList:
		manifestList, err := reg.ManifestList(remote, ref)
		if err != nil {
			return nil, err
		}
		for _, manifest := range manifestList.Manifests {
			if manifest.Platform.OS == "linux" && manifest.Platform.Architecture == "amd64" {
				manifest, err := reg.ManifestV2(remote, manifest.Digest)
				if err != nil {
					return nil, err
				}
				layers := s.parseV2Layers(manifest)
				return layers, nil
			}
		}
		return nil, errors.New("No corresponding manifest found from manifest list object")
	default:
		return nil, fmt.Errorf("Could not parse manifest type %q", manifestType)
	}
}

func (s *Server) fetchLayers(reg types.Registry, image *types.Image) (string, []string, error) {
	ref := image.Tag
	if image.SHA != "" {
		ref = image.SHA
	}

	digest, manifestType, err := reg.ManifestDigest(image.Remote, ref)
	if err != nil {
		// Some registries have no implemented the docker registry API correctly so the fall back here is to just try all the manifest types
		manifestTypes := []string{registry.MediaTypeManifestList, schema2.MediaTypeManifest, schema1.MediaTypeSignedManifest, schema1.MediaTypeManifest}
		for _, m := range manifestTypes {
			layers, manifestErr := s.handleManifest(reg, m, image.Remote, ref)
			if manifestErr != nil {
				continue
			}
			return image.String(), layers, nil
		}
		return "", nil, err
	}
	layers, err := s.handleManifest(reg, manifestType, image.Remote, digest.String())
	if err != nil {
		return "", nil, err
	}
	return digest.String(), layers, nil
}
