package clair

import (
	"net/http"
	"net/http/httptest"
	"testing"

	v1 "github.com/stackrox/scanner/api/v1"
	"github.com/stackrox/scanner/pkg/clairify/fixtures"
	"github.com/stackrox/scanner/pkg/clairify/types"
	"github.com/stretchr/testify/suite"
)

func TestClairSuite(t *testing.T) {
	suite.Run(t, new(ClairTestSuite))
}

type ClairTestSuite struct {
	suite.Suite

	client *Client
	server *httptest.Server
}

func (suite *ClairTestSuite) SetupSuite() {
	masterRouter := http.NewServeMux()
	masterRouter.HandleFunc("/v1/layers/layer1", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fixtures.GetLayerResponse))
	})
	masterRouter.HandleFunc("/v1/layers/layer2", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(fixtures.ErrorResponse))
	})
	masterRouter.HandleFunc("/v1/layers", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(fixtures.PostLayerResponse))
	})

	suite.server = httptest.NewServer(masterRouter)
	suite.client = NewClient(suite.server.URL)
}

func (suite *ClairTestSuite) TearDownSuite() {
	suite.server.Close()
}

func (suite *ClairTestSuite) TestAnalyzeImage() {
	err := suite.client.AnalyzeImage("registry", &types.Image{}, []string{"layer1", "layer2"}, map[string]string{"Authorization": "Bearer thisisbearerauth"})
	suite.NoError(err)
}

func (suite *ClairTestSuite) TestAnalyzeLayer() {
	err := suite.client.analyzeLayer("path", "layer", "parent", map[string]string{"Authorization": "Bearer auth"})
	suite.NoError(err)
}

func (suite *ClairTestSuite) TestRetrieveLayerData() {
	// If data exists
	expectedEnvelope := &v1.LayerEnvelope{
		Layer: &v1.Layer{
			Features: []v1.Feature{
				{
					Name:    "pcre3",
					Version: "2:8.35-3.3+deb8u4",
					Vulnerabilities: []v1.Vulnerability{
						{
							Name: "CVE-2017-16231",
							Link: "https://security-tracker.debian.org/tracker/CVE-2017-16231",
						},
					},
				},
			},
		},
	}
	envelope, exists, err := suite.client.RetrieveLayerData("layer1", nil)
	suite.NoError(err)
	suite.True(exists)
	suite.Equal(expectedEnvelope, envelope)

	// If data does not exist
	envelope, exists, err = suite.client.RetrieveLayerData("layer2", nil)
	suite.NoError(err)
	suite.False(exists)
	suite.Nil(envelope)
}
