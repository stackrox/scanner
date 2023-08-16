package server

import (
	"crypto/sha256"
	"fmt"
	"io"
	"runtime"

	imageManifest "github.com/containers/image/v5/manifest"
	"github.com/docker/distribution"
	"github.com/docker/distribution/manifest/manifestlist"
	manifestV1 "github.com/docker/distribution/manifest/schema1"
	manifestV2 "github.com/docker/distribution/manifest/schema2"
	"github.com/heroku/docker-registry-client/registry"
	"github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	clair "github.com/stackrox/scanner"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/clairify/types"
	"github.com/stackrox/scanner/pkg/tarutil"
)

const (
	emptyLayer = "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
)

var manifestTypes = []string{
	manifestlist.MediaTypeManifestList,
	manifestV2.MediaTypeManifest,
	registry.MediaTypeImageIndex,
	registry.MediaTypeImageManifest,
	manifestV1.MediaTypeSignedManifest,
	manifestV1.MediaTypeManifest,
}

// analyzeLayers processes all of the layers and returns the lineage for the last layer so that we can uniquely identify it
func analyzeLayers(storage database.Datastore, registry types.Registry, image *types.Image, layers []string, uncertifiedRHEL bool) (string, error) {
	var prevLayer string

	var prevLineage, lineage string
	var baseFiles *tarutil.LayerFiles
	h := sha256.New()
	for _, layer := range layers {
		layerReadCloser := &LayerDownloadReadCloser{
			Downloader: func() (io.ReadCloser, error) {
				return registry.DownloadLayer(image.Remote, digest.Digest(layer))
			},
		}

		var err error
		// baseFiles tracks the files from previous layer to help resolve paths
		baseFiles, err = clair.ProcessLayerFromReader(storage, "Docker", layer, lineage, prevLayer, prevLineage, layerReadCloser, baseFiles, uncertifiedRHEL)
		if err != nil {
			logrus.Errorf("Error analyzing layer: %v", err)
			return "", err
		}

		h.Write([]byte(layer))

		prevLineage = lineage
		lineage = fmt.Sprintf("%x", h.Sum(nil))
		prevLayer = layer
	}
	logrus.Infof("Finished analyzing all layers for image %s", image)
	return prevLineage, nil
}

// ProcessImage scans the given image.
func ProcessImage(storage database.Datastore, image *types.Image, registry, username, password string, insecure, uncertifiedRHEL bool) (string, error) {
	var reg types.Registry
	var err error
	if insecure {
		reg, err = types.InsecureDockerRegistryCreator(registry, username, password)
	} else {
		reg, err = types.DockerRegistryCreator(registry, username, password)
	}
	if err != nil {
		return "", err
	}
	digest, lineage, layer, err := process(storage, image, reg, uncertifiedRHEL)
	if err != nil {
		return digest, err
	}
	if image.SHA == "" {
		image.SHA = digest
	}
	return digest, storage.AddImage(layer, image.SHA, lineage, image.TaggedName(), &database.DatastoreOptions{
		UncertifiedRHEL: uncertifiedRHEL,
	})
}

// process fetches and analyzes the layers for the requested image returning the image digest, the lineage of the last layer and the last layer digest
func process(storage database.Datastore, image *types.Image, reg types.Registry, uncertifiedRHEL bool) (string, string, string, error) {
	logrus.Debugf("Processing image %s", image)
	digest, layers, err := FetchLayers(reg, image)
	if err != nil {
		return digest, "", "", err
	}
	if len(layers) == 0 {
		return digest, "", "", fmt.Errorf("No layers to process for image %s", image.String())
	}

	logrus.Infof("Found %v layers for image %v", len(layers), image)
	lineage, err := analyzeLayers(storage, reg, image, layers, uncertifiedRHEL)
	if err != nil {
		logrus.Errorf("Failed to analyze image %q: %v", image.String(), err)
		return digest, "", "", err
	}
	return digest, lineage, layers[len(layers)-1], err
}

func isEmptyLayer(layer string) bool {
	return layer == emptyLayer
}

func parseV1Layers(manifest *manifestV1.SignedManifest) []string {
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

func parseLayers(manifestLayers []distribution.Descriptor) []string {
	var layers []string
	for _, layer := range manifestLayers {
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
	dig, err := imageManifest.Digest(canonical)
	if err != nil {
		return dig, err
	}
	return dig, nil
}

func handleManifestLists(reg types.Registry, remote, ref string, manifests []manifestlist.ManifestDescriptor) (digest.Digest, []string, error) {
	if len(manifests) == 0 {
		return "", nil, errors.Errorf("no valid manifests found for %s:%s", remote, ref)
	}
	if len(manifests) == 1 {
		return handleManifest(reg, manifests[0].MediaType, remote, manifests[0].Digest.String())
	}
	var amdManifest manifestlist.ManifestDescriptor
	var foundAMD bool
	for _, m := range manifests {
		if m.Platform.OS != "linux" {
			continue
		}
		// Matching platform for GOARCH takes priority so return immediately
		if m.Platform.Architecture == runtime.GOARCH {
			return handleManifest(reg, m.MediaType, remote, m.Digest.String())
		}
		if m.Platform.Architecture == "amd64" {
			foundAMD = true
			amdManifest = m
		}
	}
	if foundAMD {
		return handleManifest(reg, amdManifest.MediaType, remote, amdManifest.Digest.String())
	}
	return "", nil, errors.Errorf("no manifest in list matched linux and amd64 or %s architectures: %q", runtime.GOARCH, ref)
}

func handleManifest(reg types.Registry, manifestType, remote, ref string) (digest.Digest, []string, error) {
	switch manifestType {
	case manifestV1.MediaTypeManifest:
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
	case manifestV1.MediaTypeSignedManifest:
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
	case manifestV2.MediaTypeManifest:
		manifest, err := reg.ManifestV2(remote, ref)
		if err != nil {
			return "", nil, err
		}
		dig, err := renderDigest(manifest)
		if err != nil {
			return "", nil, err
		}
		layers := parseLayers(manifest.Layers)
		return dig, layers, nil
	case registry.MediaTypeImageManifest:
		manifest, err := reg.ManifestOCI(remote, ref)
		if err != nil {
			return "", nil, err
		}
		dig, err := renderDigest(manifest)
		if err != nil {
			return "", nil, err
		}
		return dig, parseLayers(manifest.Layers), nil
	case manifestlist.MediaTypeManifestList:
		manifestList, err := reg.ManifestList(remote, ref)
		if err != nil {
			return "", nil, err
		}
		return handleManifestLists(reg, remote, ref, manifestList.Manifests)
	case registry.MediaTypeImageIndex:
		imageIndex, err := reg.ImageIndex(remote, ref)
		if err != nil {
			return "", nil, err
		}
		return handleManifestLists(reg, remote, ref, imageIndex.Manifests)
	default:
		return "", nil, fmt.Errorf("Could not parse manifest type %q", manifestType)
	}
}

// FetchLayers downloads the layers for the given image.
func FetchLayers(reg types.Registry, image *types.Image) (string, []string, error) {
	ref := image.Tag
	if image.SHA != "" {
		ref = image.SHA
	}

	d, manifestType, err := reg.ManifestDigest(image.Remote, ref)
	if err != nil {
		// Some registries have not implemented the docker registry API correctly,
		// so just try all the manifest types.
		for _, m := range manifestTypes {
			d, layers, manifestErr := handleManifest(reg, m, image.Remote, ref)
			if manifestErr != nil {
				continue
			}
			return d.String(), layers, nil
		}
		return "", nil, err
	}
	// No digest is needed from handleManifest because the manifest digest gives us the definitive digest
	_, layers, err := handleManifest(reg, manifestType, image.Remote, d.String())
	if err != nil {
		return "", nil, err
	}
	return d.String(), layers, nil
}
