package clair

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/httputil/proxy"
	v1 "github.com/stackrox/scanner/api/v1"
	"github.com/stackrox/scanner/pkg/clairify/types"
)

// Client provides access to Clair.
type Client struct {
	client   *http.Client
	endpoint string
}

// NewClient creates a new Clair client.
func NewClient(endpoint string) *Client {
	endpoint = strings.TrimRight(endpoint, "/")
	return &Client{
		client: &http.Client{
			Timeout:   1 * time.Minute,
			Transport: proxy.RoundTripper(),
		},
		endpoint: endpoint,
	}
}

// AnalyzeImage takes in a registry, image, layers to scan and the headers to pass.
// It iterates through the layers and pushes them to Clair.
func (c *Client) AnalyzeImage(registryURL string, image *types.Image, layers []string, headers map[string]string) error {
	var prevLayer string
	for _, layer := range layers {
		fullURL := fmt.Sprintf("%s/v2/%s/blobs/%s", registryURL, image.Remote, layer)
		logrus.Debugf("Analyzing layer %s for image %s", layer, image)
		if err := c.analyzeLayer(fullURL, layer, prevLayer, headers); err != nil {
			logrus.Errorf("Error analyzing layer: %v", err.Error())
			return err
		}
		prevLayer = layer
	}
	logrus.Infof("Finished analyzing all layers for image %s", image)
	return nil
}

func (c *Client) analyzeLayer(path, layerName, parentLayerName string, h map[string]string) error {
	payload := v1.LayerEnvelope{
		Layer: &v1.Layer{
			Name:       layerName,
			Path:       path,
			ParentName: parentLayerName,
			Format:     "Docker",
			Headers:    h,
		},
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	fullURL := fmt.Sprintf("%v/v1/layers", c.endpoint)
	logrus.Debugf("Pushing layer %v to Clair", path)
	request, err := http.NewRequest(http.MethodPost, fullURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}
	data, status, err := c.sendRequest(request)
	if err != nil {
		return err
	}
	if status != http.StatusCreated {
		return fmt.Errorf("Got response %d with message %s", status, strings.TrimSpace(string(data)))
	}
	return nil
}

func (c *Client) sendRequest(req *http.Request) ([]byte, int, error) {
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, -1, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

// RetrieveLayerData fetches the layer information for the passed layer.
func (c *Client) RetrieveLayerData(layer string, values url.Values) (*v1.LayerEnvelope, bool, error) {
	url := fmt.Sprintf("%v/v1/layers/%v", c.endpoint, layer)
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}
	request.URL.RawQuery = values.Encode()
	body, status, err := c.sendRequest(request)
	if err != nil {
		return nil, false, err
	}
	if status == http.StatusNotFound {
		return nil, false, nil
	}
	if status != http.StatusOK {
		return nil, false, fmt.Errorf("Unexpected status code %v: %v", status, string(body))
	}
	le := new(v1.LayerEnvelope)
	if err := json.Unmarshal(body, &le); err != nil {
		return nil, false, err
	}
	return le, true, nil
}
