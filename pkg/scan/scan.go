package server

import (
	"fmt"
	"io"

	v5Manifest "github.com/containers/image/v5/manifest"
	"github.com/docker/distribution/manifest/schema1"
	"github.com/docker/distribution/manifest/schema2"
	"github.com/heroku/docker-registry-client/registry"
	"github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	clair "github.com/stackrox/scanner"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/clairify/types"
)

const (
	emptyLayer = "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
)

func analyzeLayers(storage database.Datastore, registry types.Registry, image *types.Image, layers []string) error {
	var prevLayer string
	for _, layer := range layers {
		layerReadCloser := &layerDownloadReadCloser{
			downloader: func() (io.ReadCloser, error) {
				return registry.DownloadLayer(image.Remote, digest.Digest(layer))
			},
		}

		err := clair.ProcessLayerFromReader(storage, "Docker", layer, prevLayer, layerReadCloser)
		if err != nil {
			logrus.Errorf("Error analyzing layer: %v", err)
			return err
		}
		prevLayer = layer
	}
	logrus.Infof("Finished analyzing all layers for image %s", image)
	return nil
}

func ProcessImage(storage database.Datastore, image *types.Image, imageRequest *types.ImageRequest, username, password string) (string, error) {
	var reg types.Registry
	var err error
	if imageRequest.Insecure {
		reg, err = types.InsecureDockerRegistryCreator(imageRequest.Registry, username, password, imageRequest.UnsupportedHeadCall)
	} else {
		reg, err = types.DockerRegistryCreator(imageRequest.Registry, username, password, imageRequest.UnsupportedHeadCall)
	}
	if err != nil {
		return "", err
	}
	digest, layer, err := process(storage, image, reg)
	if err != nil {
		return "", err
	}
	if image.SHA == "" {
		image.SHA = digest
	}
	return image.SHA, storage.AddImage(layer, image.SHA, image.TaggedName())
}

func process(storage database.Datastore, image *types.Image, reg types.Registry) (string, string, error) {
	logrus.Debugf("Processing image %s", image)
	digest, layers, err := fetchLayers(reg, image)
	if err != nil {
		return digest, "", err
	}
	if len(layers) == 0 {
		return digest, "", errors.Errorf("No layers to process for image %s", image.String())
	}

	logrus.Infof("Found %v layers for image %v", len(layers), image)
	if err = analyzeLayers(storage, reg, image, layers); err != nil {
		logrus.Errorf("Failed to analyze image %q: %v", image.String(), err)
		return digest, "", err
	}
	return digest, layers[len(layers)-1], err
}

func isEmptyLayer(layer string) bool {
	return layer == emptyLayer
}

func parseV1Layers(manifest *schema1.SignedManifest) []string {
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

func parseV2Layers(manifest *schema2.DeserializedManifest) []string {
	var layers []string
	for _, layer := range manifest.Layers {
		if isEmptyLayer(layer.Digest.String()) {
			continue
		}
		layers = append(layers, layer.Digest.String())
	}
	return layers
}

type payloadGetter interface {
	Payload() (string, []byte, error)
}

func renderDigest(manifest payloadGetter) (digest.Digest, error) {
	_, canonical, err := manifest.Payload()
	if err != nil {
		return "", err
	}
	dig, err := v5Manifest.Digest(canonical)
	if err != nil {
		return dig, err
	}
	return dig, nil
}

func handleManifest(reg types.Registry, manifestType string, remote, ref string) (digest.Digest, []string, error) {
	switch manifestType {
	case schema1.MediaTypeManifest:
		manifest, err := reg.Manifest(remote, ref)
		if err != nil {
			return "", nil, err
		}
		dig, err := renderDigest(manifest)
		if err != nil {
			return "", nil, err
		}
		layers := parseV1Layers(manifest)
		return dig, layers, nil
	case schema1.MediaTypeSignedManifest:
		manifest, err := reg.SignedManifest(remote, ref)
		if err != nil {
			return "", nil, err
		}
		dig, err := renderDigest(manifest)
		if err != nil {
			return "", nil, err
		}
		layers := parseV1Layers(manifest)
		return dig, layers, nil
	case schema2.MediaTypeManifest:
		manifest, err := reg.ManifestV2(remote, ref)
		if err != nil {
			return "", nil, err
		}
		dig, err := renderDigest(manifest)
		if err != nil {
			return "", nil, err
		}
		layers := parseV2Layers(manifest)
		return dig, layers, nil

	case registry.MediaTypeManifestList:
		manifestList, err := reg.ManifestList(remote, ref)
		if err != nil {
			return "", nil, err
		}
		for _, manifest := range manifestList.Manifests {
			if manifest.Platform.OS == "linux" && manifest.Platform.Architecture == "amd64" {
				manifest, err := reg.ManifestV2(remote, manifest.Digest)
				if err != nil {
					return "", nil, err
				}
				dig, err := renderDigest(manifest)
				if err != nil {
					return "", nil, err
				}
				layers := parseV2Layers(manifest)
				return dig, layers, nil
			}
		}
		return "", nil, errors.New("No corresponding manifest found from manifest list object")
	default:
		return "", nil, fmt.Errorf("Could not parse manifest type %q", manifestType)
	}
}

func tryManifests(reg types.Registry, remote, ref string) (string, []string, error) {
	// Some registries have not implemented the docker registry API correctly so the fall back here is to just try all the manifest types
	manifestTypes := []string{registry.MediaTypeManifestList, schema2.MediaTypeManifest, schema1.MediaTypeSignedManifest, schema1.MediaTypeManifest}
	for _, m := range manifestTypes {
		digest, layers, manifestErr := handleManifest(reg, m, remote, ref)
		if manifestErr != nil {
			continue
		}
		return digest.String(), layers, nil
	}
	return "", nil, errors.Errorf("no manifest handlers returned without error for %q %q", remote, ref)
}

func fetchLayers(reg types.Registry, image *types.Image) (string, []string, error) {
	ref := image.Tag
	if image.SHA != "" {
		ref = image.SHA
	}

	if reg.UnsupportedHEADCall() {
		return tryManifests(reg, image.Remote, ref)
	}
	digest, manifestType, err := reg.ManifestDigest(image.Remote, ref)
	if err != nil {
		return "", nil, errors.Wrapf(err, "getting manifest for %q %q", image.Remote, ref)
	}
	// We do not need to get the digest from the handling of the manifest, because ManifestDigest should give us the authoritative one
	_, layers, err := handleManifest(reg, manifestType, image.Remote, digest.String())
	if err != nil {
		return "", nil, err
	}
	return digest.String(), layers, nil
}
