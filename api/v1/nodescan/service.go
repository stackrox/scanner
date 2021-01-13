package nodescan

import (
	"context"
	"sort"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/stringutils"
	apiGRPC "github.com/stackrox/scanner/api/grpc"
	"github.com/stackrox/scanner/api/v1/convert"
	"github.com/stackrox/scanner/cpe/nvdtoolscache"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/kernelparser"
	"github.com/stackrox/scanner/ext/versionfmt"
	v1 "github.com/stackrox/scanner/generated/shared/api/v1"
	k8scache "github.com/stackrox/scanner/k8s/cache"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Service interface {
	apiGRPC.APIService

	v1.NodeScanServiceServer
}

// NewService returns the service for scanning
func NewService(db database.Datastore, nvdCache nvdtoolscache.Cache, k8sCache k8scache.Cache) Service {
	return &serviceImpl{
		db:       db,
		nvdCache: nvdCache,
		k8sCache: k8sCache,
	}
}

type serviceImpl struct {
	db       database.Datastore
	nvdCache nvdtoolscache.Cache
	k8sCache k8scache.Cache
}

func filterInvalidVulns(vulns []*v1.Vulnerability) []*v1.Vulnerability {
	filteredVulns := make([]*v1.Vulnerability, 0, len(vulns))
	for _, v := range vulns {
		if v.GetMetadataV2().GetCvssV2() == nil && v.GetMetadataV2().GetCvssV3() == nil {
			continue
		}
		// This will make filter out vulns that are of form CVE- and older than 2012
		if strings.HasPrefix(v.Name, "CVE-") && v.Name < "CVE-2012" {
			continue
		}
		filteredVulns = append(filteredVulns, v)
	}
	return filteredVulns
}

func (s *serviceImpl) getNVDVulns(vendor, product, version string) ([]*v1.Vulnerability, error) {
	version, err := truncateVersion(version)
	if err != nil {
		log.Warnf("unable to truncate version %v for %v:%v: %v. Skipping...", version, vendor, product, err)
		return nil, nil
	}
	nvdVulns, err := s.nvdCache.GetVulnsForComponent(vendor, product, version)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get vulns for %v:%v:%v: %v. Skipping...", vendor, product, version, err)
	}

	vulns, err := convert.NVDVulns(nvdVulns)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to convert vulnerabilities: %v", err)
	}
	return filterInvalidVulns(vulns), nil
}

func (s *serviceImpl) evaluateLinuxKernelVulns(req *v1.GetNodeVulnerabilitiesRequest) ([]*v1.Vulnerability, error) {
	osImage := strings.ToLower(req.GetOsImage())

	var match *kernelparser.ParseMatch
	for name, parser := range kernelparser.Parsers {
		var ok bool
		match, ok = parser(req.GetKernelVersion(), osImage)
		if !ok {
			continue
		}
		if match == nil {
			log.Warnf("%s %s matched %s, but no match found", osImage, req.GetKernelVersion(), name)
			return nil, nil
		}
		break
	}
	if match != nil {
		fv := database.FeatureVersion{
			Feature: database.Feature{
				Name: match.FeatureName,
				Namespace: database.Namespace{
					Name:          match.Namespace,
					VersionFormat: match.Format,
				},
			},
			Version: match.Version,
		}

		databaseVulns, err := s.db.GetVulnerabilitiesForFeatureVersion(fv)
		if err != nil {
			return nil, err
		}

		vulns := make([]*v1.Vulnerability, 0, len(databaseVulns))
		for _, affected := range databaseVulns {
			metadata, err := convert.MetadataMap(affected.Metadata)
			if err != nil {
				log.Errorf("error converting metadata: %v", err)
			}

			vuln := &v1.Vulnerability{
				Name:        affected.Name,
				Description: affected.Description,
				Link:        affected.Link,
				MetadataV2:  metadata,
			}
			if affected.FixedBy != versionfmt.MaxVersion {
				vuln.FixedBy = affected.FixedBy
			}
			vulns = append(vulns, vuln)
		}
		sort.Slice(vulns, func(i, j int) bool {
			return vulns[i].Name < vulns[j].Name
		})
		return filterInvalidVulns(vulns), nil
	}

	return s.getNVDVulns("linux", "linux_kernel", req.GetKernelVersion())
}

func (s *serviceImpl) getKubernetesVuln(name, version string) ([]*v1.Vulnerability, error) {
	if name == "" || version == "" {
		return nil, nil
	}
	version, err := truncateVersion(version)
	if err != nil {
		log.Warnf("Unable to convert version of %s:%s - %v. Skipping...", name, version, err)
		return nil, nil
	}

	vulns := s.k8sCache.GetVulnsByComponent(name, version)
	converted, err := convertK8sVulnerabilities(version, vulns)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to convert vulnerabilities: %v", err)
	}
	return filterInvalidVulns(converted), nil
}

func (s *serviceImpl) getRuntimeVulns(containerRuntime *v1.GetNodeVulnerabilitiesRequest_ContainerRuntime) ([]*v1.Vulnerability, error) {
	if containerRuntime.GetName() == "" || containerRuntime.GetVersion() == "" {
		return nil, nil
	}
	switch containerRuntime.GetName() {
	case "docker":
		return s.getNVDVulns("docker", "docker", containerRuntime.GetVersion())
	case "crio", "cri-o":
		return s.getNVDVulns("kubernetes", "cri-o", containerRuntime.GetVersion())
	case "containerd", "runc":
		return s.getNVDVulns("linuxfoundation", containerRuntime.GetName(), containerRuntime.GetVersion())
	default:
		log.Warnf("Unsupported container runtime for node scanning: %s %s", containerRuntime.GetName(), containerRuntime.GetVersion())
	}
	return nil, nil
}

func (s *serviceImpl) GetNodeVulnerabilities(ctx context.Context, req *v1.GetNodeVulnerabilitiesRequest) (*v1.GetNodeVulnerabilitiesResponse, error) {
	if stringutils.AtLeastOneEmpty(req.GetKernelVersion(), req.GetOsImage()) {
		return nil, status.Error(codes.InvalidArgument, "both os image and kernel version are required")
	}

	var err error
	var resp v1.GetNodeVulnerabilitiesResponse

	resp.KernelVulnerabilities, err = s.evaluateLinuxKernelVulns(req)
	if err != nil {
		return nil, err
	}

	resp.KubeproxyVulnerabilities, err = s.getKubernetesVuln(k8scache.KubeProxy, req.GetKubeproxyVersion())
	if err != nil {
		return nil, err
	}

	resp.KubeletVulnerabilities, err = s.getKubernetesVuln(k8scache.Kubelet, req.GetKubeletVersion())
	if err != nil {
		return nil, err
	}

	resp.RuntimeVulnerabilities, err = s.getRuntimeVulns(req.GetRuntime())
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// RegisterServiceServer registers this service with the given gRPC Server.
func (s *serviceImpl) RegisterServiceServer(grpcServer *grpc.Server) {
	v1.RegisterNodeScanServiceServer(grpcServer, s)
}

// RegisterServiceHandler registers this service with the given gRPC Gateway endpoint.
func (s *serviceImpl) RegisterServiceHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return v1.RegisterNodeScanServiceHandler(ctx, mux, conn)
}
