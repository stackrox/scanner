package types

import (
	"fmt"
	"io"
	"net/url"

	manifestV1 "github.com/docker/distribution/manifest/schema1"
	manifestV2 "github.com/docker/distribution/manifest/schema2"
	"github.com/docker/distribution/reference"
	"github.com/heroku/docker-registry-client/registry"
	"github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	v1 "github.com/stackrox/scanner/api/v1"
)

// ClairClient interface.
type ClairClient interface {
	AnalyzeImage(registryURL string, image *Image, layers []string, headers map[string]string) error
	RetrieveLayerData(string, url.Values) (*v1.LayerEnvelope, bool, error)
}

// Registry is the Docker Registry Client interface.
type Registry interface {
	Manifest(repository, reference string) (*manifestV1.SignedManifest, error)
	SignedManifest(repository, reference string) (*manifestV1.SignedManifest, error)
	ManifestV2(repository, reference string) (*manifestV2.DeserializedManifest, error)
	ManifestList(repository, reference string) (*registry.ManifestList, error)

	ManifestDigest(repository, reference string) (digest.Digest, string, error)
	DownloadLayer(repository string, digest digest.Digest) (io.ReadCloser, error)

	GetURL() string
	GetToken() string

	GetUsername() string
	GetPassword() string
	UnsupportedHEADCall() bool
}

// DockerRegistryWrapper allows the docker registry client to be interfaced for testing.
type DockerRegistryWrapper struct {
	*registry.Registry
	Username            string
	Password            string
	UnsupportedHeadCall bool
}

// GetUsername returns the username for the registry
func (d *DockerRegistryWrapper) GetUsername() string {
	return d.Username
}

// GetPassword returns the password for the registry
func (d *DockerRegistryWrapper) GetPassword() string {
	return d.Password
}

// GetToken returns the token from the docker registry implementation.
func (d *DockerRegistryWrapper) GetToken() string {
	return d.Transport.GetToken()
}

// GetURL returns the docker registry's URL.
func (d *DockerRegistryWrapper) GetURL() string {
	return d.URL
}

// UnsupportedHEADCall returns whether or not we can use the HEAD method to fetch the manifest digests
func (d *DockerRegistryWrapper) UnsupportedHEADCall() bool {
	return d.UnsupportedHeadCall
}

// RegistryClientCreator returns an implementation of Registry.
type RegistryClientCreator func(url, username, password string, unsupportedHeadCall bool) (Registry, error)

// DockerRegistryCreator allows for registries to be interfaced.
func DockerRegistryCreator(url, username, password string, unsupportedHeadCall bool) (Registry, error) {
	reg, err := registry.New(url, username, password)
	if err != nil {
		return nil, err
	}
	return &DockerRegistryWrapper{
		Username:            username,
		Password:            password,
		UnsupportedHeadCall: unsupportedHeadCall,

		Registry: reg,
	}, nil
}

// InsecureDockerRegistryCreator allows for registries to be interfaced.
func InsecureDockerRegistryCreator(url, username, password string, unsupportedHeadCall bool) (Registry, error) {
	reg, err := registry.NewInsecure(url, username, password)
	if err != nil {
		return nil, err
	}
	return &DockerRegistryWrapper{
		Username:            username,
		Password:            password,
		UnsupportedHeadCall: unsupportedHeadCall,

		Registry: reg,
	}, nil
}

// ImageRequest is sent to add an image to Clair.
type ImageRequest struct {
	Image               string `json:"image"`
	Registry            string `json:"registry"`
	Insecure            bool   `json:"insecure"`
	UnsupportedHeadCall bool   `json:"unsupportedHeadCall"`
}

// Image contains image naming metadata.
type Image struct {
	SHA      string `json:"sha"`
	Registry string `json:"registry"`
	Remote   string `json:"remote"`
	Tag      string `json:"tag"`
}

// ImageEnvelope is returned from a scan request.
type ImageEnvelope struct {
	Image *Image `json:"image"`
}

// TaggedName returns the name with a tag if it exists
func (i *Image) TaggedName() string {
	if i.Tag == "" {
		return fmt.Sprintf("%s/%s@%s", i.Registry, i.Remote, i.SHA)
	}
	return fmt.Sprintf("%s/%s:%s", i.Registry, i.Remote, i.Tag)
}

func (i *Image) String() string {
	if i.SHA == "" {
		return fmt.Sprintf("%s/%s:%s", i.Registry, i.Remote, i.Tag)
	}
	return fmt.Sprintf("%s/%s@%s", i.Registry, i.Remote, i.SHA)
}

// GenerateImageFromString parses a docker image into the Image struct.
func GenerateImageFromString(imageStr string) (*Image, error) {
	image := new(Image)

	ref, err := reference.ParseAnyReference(imageStr)
	if err != nil {
		return image, errors.Wrapf(err, "error parsing image name %q", imageStr)
	}

	digest, ok := ref.(reference.Digested)
	if ok {
		image.SHA = digest.Digest().String()
	}

	named, ok := ref.(reference.Named)
	if ok {
		image.Registry = reference.Domain(named)
		image.Remote = reference.Path(named)
	}

	namedTagged, ok := ref.(reference.NamedTagged)
	if ok {
		image.Registry = reference.Domain(namedTagged)
		image.Remote = reference.Path(namedTagged)
		image.Tag = namedTagged.Tag()
	}

	// Default the image to latest if and only if there was no tag specific and also no SHA specified
	if image.SHA == "" && image.Tag == "" {
		image.Tag = "latest"
	}
	return image, nil
}
