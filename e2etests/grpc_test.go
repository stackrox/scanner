// +build e2e

package e2etests

import (
	"context"
	"encoding/json"
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
			{
				ComponentRequest: &v1.ComponentRequest_NvdComponent{
					NvdComponent: &v1.NVDComponentRequest{
						Vendor:  "docker",
						Product: "docker",
						Version: "19.03.0",
					},
				},
			},
		},
	}
	resp, err := client.GetVulnerabilities(context.Background(), req)
	require.NoError(t, err)

	vulnList := resp.VulnerabilitiesByComponent[v1.KubernetesComponentRequest_KUBELET.String()]
	assert.NotEmpty(t, vulnList.Vulnerabilities)
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
		Description: "In kubelet v1.13.6 and v1.14.2, containers for pods that do not specify an explicit runAsUser attempt to run as uid 0 (root) on container restart, or if the image was previously pulled to the node. If the pod specified mustRunAsNonRoot: true, the kubelet will refuse to start the container as root. If the pod did not specify mustRunAsNonRoot: true, the kubelet will run the container as uid 0.\n",
		Link:        "https://github.com/kubernetes/kubernetes/issues/78308",
		Metadata:    mBytes,
		FixedBy:     "1.14.3",
	}
	assert.Contains(t, vulnList.Vulnerabilities, cve201911245)

	vulnList = resp.VulnerabilitiesByComponent["docker:docker:19.03.0"]
	assert.NotEmpty(t, vulnList.Vulnerabilities)
	m = types.Metadata{
		CVSSv2: types.MetadataCVSSv2{
			Score:               5.0,
			Vectors:             "AV:N/AC:L/Au:N/C:N/I:P/A:N",
			ExploitabilityScore: 10.0,
			ImpactScore:         2.9,
		},
		CVSSv3: types.MetadataCVSSv3{
			Score:               7.5,
			Vectors:             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
			ExploitabilityScore: 3.9,
			ImpactScore:         3.6,
		},
	}
	mBytes, err = json.Marshal(&m)
	require.NoError(t, err)
	cve201916884 := &v1.Vulnerability{
		Name:        "CVE-2019-16884",
		Description: "runc through 1.0.0-rc8, as used in Docker through 19.03.2-ce and other products, allows AppArmor restriction bypass because libcontainer/rootfs_linux.go incorrectly checks mount targets, and thus a malicious Docker image can mount over a /proc directory.\n",
		Link:        "https://nvd.nist.gov/vuln/detail/CVE-2019-16884",
		Metadata:    mBytes,
		FixedBy:     "19.03.3",
	}
	assert.Contains(t, vulnList.Vulnerabilities, cve201916884)
}
