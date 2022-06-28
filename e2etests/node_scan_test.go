//go:build e2e
// +build e2e

package e2etests

import (
	"context"
	"fmt"
	"testing"

	v1 "github.com/stackrox/scanner/generated/scanner/api/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGRPCGetNodeVulnerabilities(t *testing.T) {
	conn := connectToScanner(t)
	client := v1.NewNodeScanServiceClient(conn)

	cases := []struct {
		request          *v1.GetNodeVulnerabilitiesRequest
		responseContains *v1.GetNodeVulnerabilitiesResponse
	}{
		{
			request: &v1.GetNodeVulnerabilitiesRequest{
				OsImage:          "Ubuntu 20.04.1 LTS",
				KernelVersion:    "5.4.0-51",
				KubeletVersion:   "1.14.2",
				KubeproxyVersion: "1.14.2",
				Runtime: &v1.GetNodeVulnerabilitiesRequest_ContainerRuntime{
					Name:    "docker",
					Version: "19.03.0",
				},
			},
			responseContains: &v1.GetNodeVulnerabilitiesResponse{
				KernelComponent: &v1.GetNodeVulnerabilitiesResponse_KernelComponent{
					Name:    "linux",
					Version: "5.4.0-51",
				},
				KernelVulnerabilities: []*v1.Vulnerability{
					{
						Name:        "CVE-2020-27675",
						Description: "An issue was discovered in the Linux kernel through 5.9.1, as used with Xen through 4.14.x. drivers/xen/events/events_base.c allows event-channel removal during the event-handling loop (a race condition). This can cause a use-after-free or NULL pointer dereference, as demonstrated by a dom0 crash via events for an in-reconfiguration paravirtualized device, aka CID-073d0552ead5.",
						Link:        "https://ubuntu.com/security/CVE-2020-27675",
						MetadataV2: &v1.Metadata{
							PublishedDateTime:    "2020-10-22T21:15Z",
							LastModifiedDateTime: "2020-12-18T14:15Z",
							CvssV2: &v1.CVSSMetadata{
								Score:               4.7,
								Vector:              "AV:L/AC:M/Au:N/C:N/I:N/A:C",
								ExploitabilityScore: 3.4,
								ImpactScore:         6.9,
							},
							CvssV3: &v1.CVSSMetadata{
								Score:               4.7,
								Vector:              "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H",
								ExploitabilityScore: 1.0,
								ImpactScore:         3.6,
							},
						},
						FixedBy: "5.4.0-59.65",
					},
				},
				KubeletVulnerabilities: []*v1.Vulnerability{
					{
						Name:        "CVE-2019-11245",
						Description: "In kubelet v1.13.6 and v1.14.2, containers for pods that do not specify an explicit runAsUser attempt to run as uid 0 (root) on container restart, or if the image was previously pulled to the node. If the pod specified mustRunAsNonRoot: true, the kubelet will refuse to start the container as root. If the pod did not specify mustRunAsNonRoot: true, the kubelet will run the container as uid 0.\n",
						Link:        "https://github.com/kubernetes/kubernetes/issues/78308",
						MetadataV2: &v1.Metadata{
							CvssV2: &v1.CVSSMetadata{
								Score:               4.6,
								Vector:              "AV:L/AC:L/Au:N/C:P/I:P/A:P",
								ExploitabilityScore: 3.9,
								ImpactScore:         6.4,
							},
							CvssV3: &v1.CVSSMetadata{
								Score:               4.9,
								Vector:              "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
								ExploitabilityScore: 1.4,
								ImpactScore:         3.4,
							},
						},
						FixedBy: "1.14.3",
					},
				},
				KubeproxyVulnerabilities: nil,
				RuntimeVulnerabilities: []*v1.Vulnerability{
					{
						Name:        "CVE-2019-16884",
						Description: "runc through 1.0.0-rc8, as used in Docker through 19.03.2-ce and other products, allows AppArmor restriction bypass because libcontainer/rootfs_linux.go incorrectly checks mount targets, and thus a malicious Docker image can mount over a /proc directory.",
						Link:        "https://nvd.nist.gov/vuln/detail/CVE-2019-16884",
						MetadataV2: &v1.Metadata{
							PublishedDateTime:    "2019-09-25T18:15Z",
							LastModifiedDateTime: "2019-10-08T03:15Z",
							CvssV2: &v1.CVSSMetadata{
								Score:               5.0,
								Vector:              "AV:N/AC:L/Au:N/C:N/I:P/A:N",
								ExploitabilityScore: 10.0,
								ImpactScore:         2.9,
							},
							CvssV3: &v1.CVSSMetadata{
								Score:               7.5,
								Vector:              "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
								ExploitabilityScore: 3.9,
								ImpactScore:         3.6,
							},
						},
					},
				},
			},
		},
		{
			request: &v1.GetNodeVulnerabilitiesRequest{
				OsImage:          "Ubuntu 20.04.1 LTS",
				KernelVersion:    "5.9.1",
				KubeletVersion:   "1.14.2",
				KubeproxyVersion: "1.14.2",
				Runtime: &v1.GetNodeVulnerabilitiesRequest_ContainerRuntime{
					Name:    "crio",
					Version: "1.16.0",
				},
			},
			responseContains: &v1.GetNodeVulnerabilitiesResponse{
				KernelVulnerabilities:    nil,
				KubeletVulnerabilities:   nil,
				KubeproxyVulnerabilities: nil,
				RuntimeVulnerabilities: []*v1.Vulnerability{
					{
						Name:        "CVE-2019-14891",
						Description: "A flaw was found in cri-o, as a result of all pod-related processes being placed in the same memory cgroup. This can result in container management (conmon) processes being killed if a workload process triggers an out-of-memory (OOM) condition for the cgroup. An attacker could abuse this flaw to get host network access on an cri-o host.",
						Link:        "https://nvd.nist.gov/vuln/detail/CVE-2019-14891",
						MetadataV2: &v1.Metadata{
							PublishedDateTime:    "2019-11-25T11:15Z",
							LastModifiedDateTime: "2020-02-28T18:10Z",
							CvssV2: &v1.CVSSMetadata{
								Score:               6.0,
								Vector:              "AV:N/AC:M/Au:S/C:P/I:P/A:P",
								ExploitabilityScore: 6.8,
								ImpactScore:         6.4,
							},
							CvssV3: &v1.CVSSMetadata{
								Score:               5.0,
								Vector:              "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L",
								ExploitabilityScore: 1.6,
								ImpactScore:         3.4,
							},
						},
						FixedBy: "1.16.1",
					},
				},
			},
		},
		{
			request: &v1.GetNodeVulnerabilitiesRequest{
				OsImage:          "Ubuntu 18.04.5 LTS",
				KernelVersion:    "5.4.0-1029-gke",
				KubeletVersion:   "1.14.2",
				KubeproxyVersion: "1.14.2",
				Runtime: &v1.GetNodeVulnerabilitiesRequest_ContainerRuntime{
					Name:    "containerd",
					Version: "1.2.0",
				},
			},
			responseContains: &v1.GetNodeVulnerabilitiesResponse{
				KernelVulnerabilities:    nil,
				KubeletVulnerabilities:   nil,
				KubeproxyVulnerabilities: nil,
				RuntimeVulnerabilities: []*v1.Vulnerability{
					{
						Name:        "CVE-2020-15157",
						Description: "In containerd (an industry-standard container runtime) before version 1.2.14 there is a credential leaking vulnerability. If a container image manifest in the OCI Image format or Docker Image V2 Schema 2 format includes a URL for the location of a specific image layer (otherwise known as a “foreign layer”), the default containerd resolver will follow that URL to attempt to download it. In v1.2.x but not 1.3.0 or later, the default containerd resolver will provide its authentication credentials if the server where the URL is located presents an HTTP 401 status code along with registry-specific HTTP headers. If an attacker publishes a public image with a manifest that directs one of the layers to be fetched from a web server they control and they trick a user or system into pulling the image, they can obtain the credentials used for pulling that image. In some cases, this may be the user's username and password for the registry. In other cases, this may be the credentials attached to the cloud virtual instance which can grant access to other cloud resources in the account. The default containerd resolver is used by the cri-containerd plugin (which can be used by Kubernetes), the ctr development tool, and other client programs that have explicitly linked against it. This vulnerability has been fixed in containerd 1.2.14. containerd 1.3 and later are not affected. If you are using containerd 1.3 or later, you are not affected. If you are using cri-containerd in the 1.2 series or prior, you should ensure you only pull images from trusted sources. Other container runtimes built on top of containerd but not using the default resolver (such as Docker) are not affected.",
						Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-15157",
						MetadataV2: &v1.Metadata{
							PublishedDateTime:    "2020-10-16T17:15Z",
							LastModifiedDateTime: "2020-10-29T22:06Z",
							CvssV2: &v1.CVSSMetadata{
								Score:               2.6,
								Vector:              "AV:N/AC:H/Au:N/C:P/I:N/A:N",
								ExploitabilityScore: 4.9,
								ImpactScore:         2.9,
							},
							CvssV3: &v1.CVSSMetadata{
								Score:               6.1,
								Vector:              "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N",
								ExploitabilityScore: 1.6,
								ImpactScore:         4.0,
							},
						},
						FixedBy: "1.2.14",
					},
				},
			},
		},
		{
			request: &v1.GetNodeVulnerabilitiesRequest{
				OsImage:          "Red Hat Enterprise Linux CoreOS 47.84.202202070903-0 (Ootpa)",
				KernelVersion:    "4.18.0-305.34.2.el8_4.x86_64",
				KubeletVersion:   "v1.20.11+e880017",
				KubeproxyVersion: "v1.20.11+e880017",
				Runtime: &v1.GetNodeVulnerabilitiesRequest_ContainerRuntime{
					Name:    "cri-o",
					Version: "1.20.6-7.rhaos4.7.gitd7f3909.el8",
				},
			},
			responseContains: &v1.GetNodeVulnerabilitiesResponse{
				KernelVulnerabilities:    nil,
				KubeletVulnerabilities:   nil,
				KubeproxyVulnerabilities: nil,
				RuntimeVulnerabilities:   nil,
				Notes:                    []v1.NodeNote{v1.NodeNote_NODE_UNSUPPORTED},
			},
		},
	}

	contains := func(t *testing.T, foundVulns, expectedContains []*v1.Vulnerability) {
		// Prune last modified time
		for _, v := range foundVulns {
			v.MetadataV2.LastModifiedDateTime = ""
		}
		if expectedContains != nil {
			for _, contains := range expectedContains {
				contains.MetadataV2.LastModifiedDateTime = ""
				if !assert.Contains(t, foundVulns, contains) {
					fmt.Printf("Found vulns: %v\n", foundVulns)
					fmt.Printf("Expected vuln: %v\n", contains)
				}
			}
		}
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			resp, err := client.GetNodeVulnerabilities(context.Background(), c.request)
			require.NoError(t, err)
			contains(t, resp.KernelVulnerabilities, c.responseContains.KernelVulnerabilities)
			contains(t, resp.RuntimeVulnerabilities, c.responseContains.RuntimeVulnerabilities)
			contains(t, resp.KubeletVulnerabilities, c.responseContains.KubeletVulnerabilities)
			contains(t, resp.KubeproxyVulnerabilities, c.responseContains.KubeproxyVulnerabilities)
			assert.Equal(t, c.responseContains.Notes, resp.Notes)
		})
	}
}

func TestNodeKernelVulnerabilities(t *testing.T) {
	conn := connectToScanner(t)
	client := v1.NewNodeScanServiceClient(conn)

	type expectedCVE struct {
		id      string
		fixedBy string
	}

	cases := []struct {
		osImage       string
		kernelVersion string

		expectedOS              string
		expectedKernelComponent *v1.GetNodeVulnerabilitiesResponse_KernelComponent
		expectedCVEs            []expectedCVE
		unexpectedCVEs          []string
		expectedNotes           []v1.NodeNote
	}{
		// Ubuntu
		{
			osImage:       "Ubuntu 20.04.1 LTS",
			kernelVersion: "5.4.0-51",

			expectedOS: "ubuntu:20.04",
			expectedKernelComponent: &v1.GetNodeVulnerabilitiesResponse_KernelComponent{
				Name:    "linux",
				Version: "5.4.0-51",
			},
			expectedCVEs: []expectedCVE{
				{
					id:      "CVE-2020-27675",
					fixedBy: "5.4.0-59.65",
				},
			},
		},
		{
			osImage:       "Ubuntu 16.04.7 LTS",
			kernelVersion: "4.15.0-1050-gcp",

			expectedOS: "ubuntu:16.04",
			expectedKernelComponent: &v1.GetNodeVulnerabilitiesResponse_KernelComponent{
				Name:    "linux-gcp",
				Version: "4.15.0-1050",
			},
			expectedCVEs: []expectedCVE{
				{
					id:      "CVE-2020-27675",
					fixedBy: "4.15.0-1091.104~16.04.1",
				},
				{
					id:      "CVE-2019-2182",
					fixedBy: "4.15.0-1058.62",
				},
			},
		},
		{
			osImage:       "Ubuntu 16.04.7 LTS",
			kernelVersion: "4.2.0-1119-aws",

			expectedOS: "ubuntu:16.04",
			expectedKernelComponent: &v1.GetNodeVulnerabilitiesResponse_KernelComponent{
				Name:    "linux-aws",
				Version: "4.2.0-1119",
			},
			expectedCVEs: []expectedCVE{
				{
					id:      "CVE-2020-27675",
					fixedBy: "4.4.0-1119.133",
				},
			},
			unexpectedCVEs: []string{
				"CVE-2019-2182", // AWS flavor of Ubuntu on 16.04 is not vulnerable
			},
		},
		{
			osImage:       "Ubuntu 18.04.5 LTS",
			kernelVersion: "4.15.0-1050-aws",

			expectedOS: "ubuntu:18.04",
			expectedKernelComponent: &v1.GetNodeVulnerabilitiesResponse_KernelComponent{
				Name:    "linux-aws",
				Version: "4.15.0-1050",
			},
			expectedCVEs: []expectedCVE{
				{
					id:      "CVE-2020-27675",
					fixedBy: "4.15.0-1091.96",
				},
				{
					// AWS Flavor on 18.04 is vulnerable and should have a different fixed by
					id:      "CVE-2019-2182",
					fixedBy: "4.15.0-1063.67",
				},
			},
		},
		{
			osImage:       "Ubuntu 18.04.5 LTS",
			kernelVersion: "5.3.0-1019-gke",

			expectedOS: "ubuntu:18.04",
			expectedKernelComponent: &v1.GetNodeVulnerabilitiesResponse_KernelComponent{
				Name:    "linux-gke-5.3",
				Version: "5.3.0-1019",
			},
			expectedCVEs: []expectedCVE{
				{
					id:      "CVE-2020-14381",
					fixedBy: "5.3.0-1020.22~18.04.1",
				},
			},
			unexpectedCVEs: []string{"CVE-2019-2182"},
		},
		// Debian
		{
			osImage:       "Debian GNU/Linux 9 (stretch)",
			kernelVersion: "4.9.0-11-amd64",

			expectedOS: "debian:9",
			expectedKernelComponent: &v1.GetNodeVulnerabilitiesResponse_KernelComponent{
				Name:    "linux",
				Version: "4.9.0-11-amd64",
			},
			expectedCVEs: []expectedCVE{
				{
					id:      "CVE-2020-27675",
					fixedBy: "4.9.246-1",
				},
				{
					id:      "CVE-2020-14381",
					fixedBy: "4.9.228-1",
				},
			},
		},
		// RHEL
		{
			osImage:       "OpenShift Enterprise",
			kernelVersion: "3.10.0-1127.el7.x86_64",

			expectedOS: "centos:7",
			expectedKernelComponent: &v1.GetNodeVulnerabilitiesResponse_KernelComponent{
				Name:    "kernel",
				Version: "3.10.0-1127.el7.x86_64",
			},
			expectedCVEs: []expectedCVE{
				{
					id: "CVE-2020-14381",
				},
			},
			unexpectedCVEs: []string{"CVE-2020-27675", "CVE-2019-2182"},
		},
		{
			osImage:       "Red Hat Enterprise Linux Server 7.8 (Maipo)",
			kernelVersion: "3.10.0-1127.19.1.el7.x86_64",

			expectedOS: "centos:7",
			expectedKernelComponent: &v1.GetNodeVulnerabilitiesResponse_KernelComponent{
				Name:    "kernel",
				Version: "3.10.0-1127.19.1.el7.x86_64",
			},
			expectedCVEs: []expectedCVE{
				{
					id: "CVE-2020-14381",
				},
			},
			unexpectedCVEs: []string{"CVE-2020-27675", "CVE-2019-2182"},
		},
		{
			osImage:       "CentOS Linux 7 (Core)",
			kernelVersion: "3.10.0-957.12.2.el7.x86_64",

			expectedOS: "centos:7",
			expectedKernelComponent: &v1.GetNodeVulnerabilitiesResponse_KernelComponent{
				Name:    "kernel",
				Version: "3.10.0-957.12.2.el7.x86_64",
			},
			expectedCVEs: []expectedCVE{
				{
					id: "CVE-2020-14381",
				},
			},
			unexpectedCVEs: []string{"CVE-2020-27675", "CVE-2019-2182"},
		},
		{
			osImage:       "Red Hat Enterprise Linux CoreOS 45.82.202008101249-0 (Ootpa)",
			kernelVersion: "4.18.0-193.14.3.el8_2.x86_64",

			expectedOS:              "",
			expectedKernelComponent: nil,
			expectedCVEs:            nil,
			expectedNotes:           []v1.NodeNote{v1.NodeNote_NODE_UNSUPPORTED},
		},
		// Amzn
		{
			osImage:       "Amazon Linux 2",
			kernelVersion: "4.14.177-139.253.amzn2.x86_64",

			expectedOS: "amzn:2",
			expectedKernelComponent: &v1.GetNodeVulnerabilitiesResponse_KernelComponent{
				Name:    "kernel",
				Version: "4.14.177-139.253.amzn2.x86_64",
			},
			expectedCVEs: []expectedCVE{
				{
					id:      "ALAS2-2020-1488",
					fixedBy: "4.14.193-149.317.amzn2",
				},
				{
					id:      "CVE-2020-14386",
					fixedBy: "4.14.193-149.317.amzn2",
				},
			},
		},
		{
			osImage:       "Docker Desktop",
			kernelVersion: "5.4.39-linuxkit",

			expectedOS: "",
			expectedKernelComponent: &v1.GetNodeVulnerabilitiesResponse_KernelComponent{
				Name:    "kernel",
				Version: "5.4.39-linuxkit",
			},
			expectedCVEs: []expectedCVE{
				{
					id:      "CVE-2020-14381",
					fixedBy: "5.6",
				},
			},
		},
		// Garden
		{
			osImage:       "Garden Linux 184.0",
			kernelVersion: "5.4.0-5-cloud-amd64",

			expectedOS: "debian:11",
			expectedKernelComponent: &v1.GetNodeVulnerabilitiesResponse_KernelComponent{
				Name:    "linux",
				Version: "5.4.0-5-cloud-amd64",
			},
			expectedCVEs: []expectedCVE{
				{
					id:      "CVE-2020-27675",
					fixedBy: "5.9.6-1",
				},
				{
					id:      "CVE-2020-14381",
					fixedBy: "5.5.13-1",
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(fmt.Sprintf("%s-%s", c.osImage, c.kernelVersion), func(t *testing.T) {
			resp, err := client.GetNodeVulnerabilities(context.Background(), &v1.GetNodeVulnerabilitiesRequest{
				OsImage:       c.osImage,
				KernelVersion: c.kernelVersion,
			})
			require.NoError(t, err)

			assert.Equal(t, c.expectedNotes, resp.Notes)
			assert.Equal(t, c.expectedOS, resp.GetOperatingSystem())
			assert.Equal(t, c.expectedKernelComponent, resp.KernelComponent)

			if len(resp.GetKernelVulnerabilities()) < len(c.expectedCVEs) {
				assert.FailNowf(t, "mismatch between number of kernel vulns found", "expected vulns: %d vs %d", len(resp.GetKernelVulnerabilities()), len(c.expectedCVEs))
			}

			// validate found vulns
			for _, vuln := range resp.GetKernelVulnerabilities() {
				assert.NotEmpty(t, vuln.GetName())
				assert.NotEmpty(t, vuln.GetDescription())
				assert.NotEmpty(t, vuln.GetLink())

				metadata := vuln.GetMetadataV2()
				assert.NotNil(t, metadata)
				assert.False(t, metadata.GetCvssV2() == metadata.GetCvssV3())
				assert.NotEmpty(t, metadata.GetPublishedDateTime())
			}

		OUTER:
			for _, expectedCVE := range c.expectedCVEs {
				for _, vuln := range resp.GetKernelVulnerabilities() {
					if vuln.GetName() == expectedCVE.id {
						assert.Equal(t, expectedCVE.fixedBy, vuln.GetFixedBy())
						continue OUTER
					}
				}
				assert.Failf(t, "missing vuln", "did not find vuln: %v", expectedCVE.id)
			}
			for _, unexpectedCVE := range c.unexpectedCVEs {
				for _, vuln := range resp.GetKernelVulnerabilities() {
					assert.NotEqual(t, unexpectedCVE, vuln.GetName())
				}
			}
		})
	}
}
