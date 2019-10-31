package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	v1 "github.com/stackrox/scanner/api/v1"
	"github.com/stackrox/scanner/pkg/clairify/types"
)

// Export these timeouts so that the caller can adjust them as necessary
var (
	GetTimeout  = 20 * time.Second
	ScanTimeout = 2 * time.Minute
	PingTimeout = 5 * time.Second
)

// Clairify is the client for the Clairify extension.
type Clairify struct {
	client   *http.Client
	endpoint string
	insecure bool
}

type errorEnvelope struct {
	Error *v1.Error `json:"Error"`
}

// New returns a new Clairify client instance.
func New(endpoint string, insecure bool) *Clairify {
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
	}
	return &Clairify{
		client:   httpClient,
		endpoint: endpoint,
		insecure: insecure,
	}
}

// NewWithClient returns a new Clairify client instance based on the passed HTTP client
func NewWithClient(endpoint string, insecure bool, client *http.Client) *Clairify {
	return &Clairify{
		client:   client,
		endpoint: endpoint,
		insecure: insecure,
	}
}

func (c *Clairify) sendRequest(request *http.Request, timeout time.Duration) ([]byte, error) {
	request.Header.Set("Content-Type", "application/json")
	ctx, cancel := context.WithTimeout(request.Context(), timeout)
	defer cancel()

	request = request.WithContext(ctx)
	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return nil, ErrorScanNotFound
	}
	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	var envelope errorEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, err
	}
	if envelope.Error != nil {
		return nil, errors.New(envelope.Error.Message)
	}
	return data, nil
}

func encodeValues(features, vulnerabilities bool) url.Values {
	values := make(url.Values)
	if features {
		values.Add("features", "true")
	}
	if vulnerabilities {
		values.Add("vulnerabilities", "true")
	}
	return values
}

// Ping verifies that Clairify is accessible.
func (c *Clairify) Ping() error {
	request, err := http.NewRequest("GET", c.endpoint+"/clairify/ping", nil)
	if err != nil {
		return err
	}
	_, err = c.sendRequest(request, PingTimeout)
	return err
}

// AddImage contacts Clairify to push a specific image to Clair.
func (c *Clairify) AddImage(username, password string, req *types.ImageRequest) (*types.Image, error) {
	// Due to the long timeout for adding an image, always ping before to try to minimize the chance that
	// Clairify is not there
	if err := c.Ping(); err != nil {
		return nil, err
	}

	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest("POST", c.endpoint+"/clairify/image", bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}
	request.SetBasicAuth(username, password)
	imageData, err := c.sendRequest(request, ScanTimeout)
	if err != nil {
		return nil, err
	}

	var imageEnvelope types.ImageEnvelope
	if err := json.Unmarshal(imageData, &imageEnvelope); err != nil {
		return nil, err
	}
	return imageEnvelope.Image, err
}

// RetrieveImageDataBySHA contacts Clairify to fetch vulnerability data by the image SHA.
func (c *Clairify) RetrieveImageDataBySHA(sha string, features, vulnerabilities bool) (*v1.LayerEnvelope, error) {
	values := encodeValues(features, vulnerabilities)
	request, err := http.NewRequest("GET", c.endpoint+"/clairify/sha/"+sha, nil)
	if err != nil {
		return nil, err
	}
	request.URL.RawQuery = values.Encode()
	envelopeData, err := c.sendRequest(request, GetTimeout)
	if err != nil {
		return nil, err
	}
	var layerEnvelope v1.LayerEnvelope
	if err := json.Unmarshal(envelopeData, &layerEnvelope); err != nil {
		return nil, err
	}
	return &layerEnvelope, err
}

// RetrieveImageDataByName contacts Clairify to fetch vulnerability data by the image name.
func (c *Clairify) RetrieveImageDataByName(image *types.Image, features, vulnerabilities bool) (*v1.LayerEnvelope, error) {
	values := encodeValues(features, vulnerabilities)
	url := fmt.Sprintf("%s/clairify/image/%s/%s/%s", c.endpoint, image.Registry, image.Remote, image.Tag)
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	request.URL.RawQuery = values.Encode()
	envelopeData, err := c.sendRequest(request, GetTimeout)
	if err != nil {
		return nil, err
	}
	var layerEnvelope v1.LayerEnvelope
	if err := json.Unmarshal(envelopeData, &layerEnvelope); err != nil {
		return nil, err
	}
	return &layerEnvelope, err
}
