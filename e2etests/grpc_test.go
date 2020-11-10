// +build e2e

package e2etests

import (
	"context"
	"encoding/json"
	"github.com/sirupsen/logrus"
	"testing"

	v1 "github.com/stackrox/scanner/generated/api/v1"
	"github.com/stackrox/scanner/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGRPCScanImage(t *testing.T) {
	conn := connectToScanner(t)
	client := v1.NewScanServiceClient(conn)
	scanImageResp := scanPublicDockerHubImage(client, "nginx", t)

	getScanResp, err := client.GetScan(context.Background(), &v1.GetScanRequest{
		ImageSpec: &v1.ImageSpec{Image: scanImageResp.Image.GetImage()},
	})
	require.NoError(t, err)
	assert.NotZero(t, len(getScanResp.GetImage().GetFeatures()))
}

func TestGRPCGetVulnerabilities(t *testing.T) {
	conn := connectToScanner(t)
	client := v1.NewScanServiceClient(conn)

	m := types.Metadata{
		CVSSv2: types.MetadataCVSSv2{
			Score:               4.6,
			Vectors:             "AV:L/AC:L/Au:N/C:P/I:P/A:P",
			ExploitabilityScore: 3.9,
			ImpactScore:         6.4,
		},
		CVSSv3: types.MetadataCVSSv3{
			Score:               4.9,
			Vectors:             "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
			ExploitabilityScore: 1.4,
			ImpactScore:         3.4,
		},
	}
	mBytes, err := json.Marshal(&m)
	require.NoError(t, err)
	cve201911245 := &v1.Vulnerability{
		Name:        "CVE-2019-11245",
		Description: "In kubelet v1.13.6 and v1.14.2, containers for pods that do not specify an explicit runAsUser attempt to run as uid 0 (root) on container restart, or if the image was previously pulled to the node. If the pod specified mustRunAsNonRoot: true, the kubelet will refuse to start the container as root. If the pod did not specify mustRunAsNonRoot: true, the kubelet will run the container as uid 0.",
		Link:        "https://github.com/kubernetes/kubernetes/issues/78308",
		Metadata:    mBytes,
		FixedBy:     "1.14.3",
	}

	req := &v1.GetVulnerabilitiesRequest{
		Components: []*v1.ComponentRequest{
			{
				ComponentRequest: &v1.ComponentRequest_K8SComponent{
					K8SComponent: &v1.KubernetesComponentRequest{
						Component: v1.KubernetesComponentRequest_KUBELET,
						Version:   "1.14.2",
					},
				},
			},
		},
	}
	resp, err := client.GetVulnerabilities(context.Background(), req)
	require.NoError(t, err)
	vulnList := resp.VulnerabilitiesByComponent[v1.KubernetesComponentRequest_KUBELET.String()]
	logrus.Infof("Returned vulnList: %v", vulnList)
	assert.NotEmpty(t, vulnList)
	assert.Contains(t, vulnList.Vulnerabilities, cve201911245)
}
