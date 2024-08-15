package benchmarks

import (
	"io"
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/stackrox/scanner/pkg/clairify/types"
	server "github.com/stackrox/scanner/pkg/scan"
	"github.com/stretchr/testify/require"
)

type layerReadCloser struct {
	*server.LayerDownloadReadCloser
	Name string
}

// MustGetLayerReadClosers gets the io.ReadCloser to download each layer in the given image.
func MustGetLayerReadClosers(b *testing.B, imageName string) []*layerReadCloser {
	reg, err := types.InsecureDockerRegistryCreator("https://registry-1.docker.io", "", "")
	require.NoError(b, err)

	image, err := types.GenerateImageFromString(imageName)
	require.NoError(b, err)

	_, layerNames, err := server.FetchLayers(reg, image)
	require.NoError(b, err)

	layerReadClosers := make([]*layerReadCloser, 0, len(layerNames))

	for _, layerName := range layerNames {
		layerReadClosers = append(layerReadClosers, &layerReadCloser{
			LayerDownloadReadCloser: getLayerDownloadReadCloser(reg, image, layerName),
			Name:                    layerName,
		})
	}

	return layerReadClosers
}

func getLayerDownloadReadCloser(reg types.Registry, image *types.Image, layerName string) *server.LayerDownloadReadCloser {
	return &server.LayerDownloadReadCloser{
		Downloader: func() (io.ReadCloser, error) {
			dig, err := digest.Parse(layerName)
			if err != nil {
				return nil, errors.Wrapf(err, "invalid layer digest %q", layerName)
			}
			return reg.DownloadLayer(image.Remote, dig)
		},
	}
}
