package server

import (
	"net/url"
	"testing"

	"github.com/docker/distribution"
	"github.com/docker/distribution/manifest/schema1"
	"github.com/docker/distribution/manifest/schema2"
	"github.com/heroku/docker-registry-client/registry"
	"github.com/opencontainers/go-digest"
	v1 "github.com/stackrox/scanner/api/v1"
	"github.com/stackrox/scanner/pkg/clairify/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type registryMock struct {
	mock.Mock
}

func (m *registryMock) Manifest(repository, reference string) (*schema1.SignedManifest, error) {
	args := m.Called(repository, reference)
	return args.Get(0).(*schema1.SignedManifest), args.Error(1)
}
func (m *registryMock) ManifestV2(repository, reference string) (*schema2.DeserializedManifest, error) {
	args := m.Called(repository, reference)
	return args.Get(0).(*schema2.DeserializedManifest), args.Error(1)
}
func (m *registryMock) ManifestDigest(repository, reference string) (digest.Digest, string, error) {
	args := m.Called(repository, reference)
	return args.Get(0).(digest.Digest), args.String(1), args.Error(2)
}
func (m *registryMock) SignedManifest(repository, reference string) (*schema1.SignedManifest, error) {
	args := m.Called(repository, reference)
	return args.Get(0).(*schema1.SignedManifest), args.Error(1)
}
func (m *registryMock) ManifestList(repository, reference string) (*registry.ManifestList, error) {
	args := m.Called(repository, reference)
	return args.Get(0).(*registry.ManifestList), args.Error(1)
}

func (m *registryMock) GetURL() string {
	args := m.Called()
	return args.String(0)
}

func (m *registryMock) GetToken() string {
	args := m.Called()
	return args.String(0)
}

func (m *registryMock) GetUsername() string {
	args := m.Called()
	return args.String(0)
}

func (m *registryMock) GetPassword() string {
	args := m.Called()
	return args.String(0)
}

type ClairClientMock struct {
	mock.Mock
}

func (c *ClairClientMock) AnalyzeImage(registryURL string, image *types.Image, layers []string, headers map[string]string) error {
	args := c.Called(registryURL, image, layers, headers)
	return args.Error(0)
}

func (c *ClairClientMock) RetrieveLayerData(layer string, values url.Values) (*v1.LayerEnvelope, bool, error) {
	args := c.Called(layer, values)
	return args.Get(0).(*v1.LayerEnvelope), args.Bool(1), args.Error(2)
}

func TestProcess(t *testing.T) {
	t.Parallel()

	registryMock := &registryMock{}
	registryMock.On("GetURL").Return("docker.io")
	registryMock.On("GetToken").Return("token")
	registryMock.On("GetUsername").Return("username")
	registryMock.On("GetPassword").Return("password")

	clairMock := &ClairClientMock{}
	s := &Server{
		cc: clairMock,
	}
	image := &types.Image{
		Registry: "docker.io",
		Remote:   "library/nginx",
		Tag:      "1.10",
	}
	clairMock.On("AnalyzeImage", "docker.io", image, []string{"layer1", "layer2"}, map[string]string{"Authorization": "Bearer token"}).Return(nil)

	// if no error on v2 then return digest and layers
	v2Manifest := &schema2.DeserializedManifest{
		Manifest: schema2.Manifest{
			Config: distribution.Descriptor{
				Digest: "sha",
			},
			Layers: []distribution.Descriptor{
				{
					Digest: "layer1",
				},
				{
					Digest: emptyLayer,
				},
				{
					Digest: "layer2",
				},
			},
		},
	}

	registryMock.On("ManifestDigest", image.Remote, image.Tag).Return(digest.Digest("sha"), schema2.MediaTypeManifest, nil)

	registryMock.On("ManifestV2", image.Remote, "sha").Return(v2Manifest, nil)

	sha, lastLayer, err := s.process(image, registryMock)
	assert.NoError(t, err)
	assert.Equal(t, "sha", sha)
	assert.Equal(t, "layer2", lastLayer)
}

func TestFetchLayers(t *testing.T) {
	t.Parallel()
	registryMock := &registryMock{}
	s := &Server{}
	image := &types.Image{
		Registry: "docker.io",
		Remote:   "library/nginx",
		Tag:      "1.10",
	}

	// if no error on v2 then return digest and layers
	v2Manifest := &schema2.DeserializedManifest{
		Manifest: schema2.Manifest{
			Config: distribution.Descriptor{
				Digest: "sha",
			},
			Layers: []distribution.Descriptor{
				{
					Digest: "layer1",
				},
				{
					Digest: emptyLayer,
				},
				{
					Digest: "layer2",
				},
			},
		},
	}

	registryMock.On("ManifestDigest", image.Remote, image.Tag).Return(digest.Digest("sha"), schema2.MediaTypeManifest, nil)

	registryMock.On("ManifestV2", image.Remote, "sha").Return(v2Manifest, nil)

	// Returned v2 manifest so should call that
	imageDigest, layers, err := s.fetchLayers(registryMock, image)
	assert.NoError(t, err)
	assert.Equal(t, "sha", imageDigest)
	assert.Equal(t, []string{"layer1", "layer2"}, layers)
}
