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
			{
				ComponentRequest: &v1.ComponentRequest_NvdComponent{
					NvdComponent: &v1.NVDComponentRequest{
						Vendor:  "kubernetes",
						Product: "cri-o",
						Version: "1.16.0",
					},
				},
			},
			{
				ComponentRequest: &v1.ComponentRequest_NvdComponent{
					NvdComponent: &v1.NVDComponentRequest{
						Vendor:  "linuxfoundation",
						Product: "containerd",
						Version: "1.2.0",
					},
				},
			},
			{
				ComponentRequest: &v1.ComponentRequest_NvdComponent{
					NvdComponent: &v1.NVDComponentRequest{
						Vendor:  "linux",
						Product: "linux_kernel",
						Version: "5.9.1",
					},
				},
			},
		},
	}
	resp, err := client.GetVulnerabilities(context.Background(), req)
	require.NoError(t, err)

	// kubelet
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

	// docker
	vulnList = resp.VulnerabilitiesByComponent["docker:docker:19.03.0"]
	assert.NotEmpty(t, vulnList.Vulnerabilities)
	m = types.Metadata{
		PublishedDateTime:    "2019-09-25T18:15Z",
		LastModifiedDateTime: "2019-10-08T03:15Z",
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
		Description: "runc through 1.0.0-rc8, as used in Docker through 19.03.2-ce and other products, allows AppArmor restriction bypass because libcontainer/rootfs_linux.go incorrectly checks mount targets, and thus a malicious Docker image can mount over a /proc directory.",
		Link:        "https://nvd.nist.gov/vuln/detail/CVE-2019-16884",
		Metadata:    mBytes,
	}
	assert.Contains(t, vulnList.Vulnerabilities, cve201916884)

	// cri-o
	vulnList = resp.VulnerabilitiesByComponent["kubernetes:cri-o:1.16.0"]
	assert.NotEmpty(t, vulnList.Vulnerabilities)
	m = types.Metadata{
		PublishedDateTime:    "2019-11-25T11:15Z",
		LastModifiedDateTime: "2020-02-28T18:10Z",
		CVSSv2: types.MetadataCVSSv2{
			Score:               6.0,
			Vectors:             "AV:N/AC:M/Au:S/C:P/I:P/A:P",
			ExploitabilityScore: 6.8,
			ImpactScore:         6.4,
		},
		CVSSv3: types.MetadataCVSSv3{
			Score:               5.0,
			Vectors:             "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L",
			ExploitabilityScore: 1.6,
			ImpactScore:         3.4,
		},
	}
	mBytes, err = json.Marshal(&m)
	require.NoError(t, err)
	cve201914891 := &v1.Vulnerability{
		Name:        "CVE-2019-14891",
		Description: "A flaw was found in cri-o, as a result of all pod-related processes being placed in the same memory cgroup. This can result in container management (conmon) processes being killed if a workload process triggers an out-of-memory (OOM) condition for the cgroup. An attacker could abuse this flaw to get host network access on an cri-o host.",
		Link:        "https://nvd.nist.gov/vuln/detail/CVE-2019-14891",
		Metadata:    mBytes,
		FixedBy:     "1.16.1",
	}
	assert.Contains(t, vulnList.Vulnerabilities, cve201914891)

	// containerd
	vulnList = resp.VulnerabilitiesByComponent["linuxfoundation:containerd:1.2.0"]
	assert.NotEmpty(t, vulnList.Vulnerabilities)
	m = types.Metadata{
		PublishedDateTime:    "2020-10-16T17:15Z",
		LastModifiedDateTime: "2020-10-29T22:06Z",
		CVSSv2: types.MetadataCVSSv2{
			Score:               4.3,
			Vectors:             "AV:N/AC:M/Au:N/C:P/I:N/A:N",
			ExploitabilityScore: 8.6,
			ImpactScore:         2.9,
		},
		CVSSv3: types.MetadataCVSSv3{
			Score:               6.1,
			Vectors:             "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N",
			ExploitabilityScore: 1.6,
			ImpactScore:         4.0,
		},
	}
	mBytes, err = json.Marshal(&m)
	require.NoError(t, err)
	cve202015157 := &v1.Vulnerability{
		Name:        "CVE-2020-15157",
		Description: "In containerd (an industry-standard container runtime) before version 1.2.14 there is a credential leaking vulnerability. If a container image manifest in the OCI Image format or Docker Image V2 Schema 2 format includes a URL for the location of a specific image layer (otherwise known as a “foreign layer”), the default containerd resolver will follow that URL to attempt to download it. In v1.2.x but not 1.3.0 or later, the default containerd resolver will provide its authentication credentials if the server where the URL is located presents an HTTP 401 status code along with registry-specific HTTP headers. If an attacker publishes a public image with a manifest that directs one of the layers to be fetched from a web server they control and they trick a user or system into pulling the image, they can obtain the credentials used for pulling that image. In some cases, this may be the user's username and password for the registry. In other cases, this may be the credentials attached to the cloud virtual instance which can grant access to other cloud resources in the account. The default containerd resolver is used by the cri-containerd plugin (which can be used by Kubernetes), the ctr development tool, and other client programs that have explicitly linked against it. This vulnerability has been fixed in containerd 1.2.14. containerd 1.3 and later are not affected. If you are using containerd 1.3 or later, you are not affected. If you are using cri-containerd in the 1.2 series or prior, you should ensure you only pull images from trusted sources. Other container runtimes built on top of containerd but not using the default resolver (such as Docker) are not affected.",
		Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-15157",
		Metadata:    mBytes,
		FixedBy:     "1.2.14",
	}
	assert.Contains(t, vulnList.Vulnerabilities, cve202015157)

	// linux kernel
	vulnList = resp.VulnerabilitiesByComponent["linux:linux_kernel:5.9.1"]
	assert.NotEmpty(t, vulnList.Vulnerabilities)
	m = types.Metadata{
		PublishedDateTime: "2020-10-22T21:15Z",
		LastModifiedDateTime: "2020-11-11T06:15Z",
		CVSSv2: types.MetadataCVSSv2{
			Score:               4.7,
			Vectors:             "AV:L/AC:M/Au:N/C:N/I:N/A:C",
			ExploitabilityScore: 3.4,
			ImpactScore:         6.9,
		},
		CVSSv3: types.MetadataCVSSv3{
			Score:               4.7,
			Vectors:             "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H",
			ExploitabilityScore: 1.0,
			ImpactScore:         3.6,
		},
	}
	mBytes, err = json.Marshal(&m)
	require.NoError(t, err)
	cve202027675 := &v1.Vulnerability{
		Name:        "CVE-2020-27675",
		Description: "An issue was discovered in the Linux kernel through 5.9.1, as used with Xen through 4.14.x. drivers/xen/events/events_base.c allows event-channel removal during the event-handling loop (a race condition). This can cause a use-after-free or NULL pointer dereference, as demonstrated by a dom0 crash via events for an in-reconfiguration paravirtualized device, aka CID-073d0552ead5.",
		Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-27675",
		Metadata:    mBytes,
		FixedBy:     "",
	}
	assert.Contains(t, vulnList.Vulnerabilities, cve202027675)
}
