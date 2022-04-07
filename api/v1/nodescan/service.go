package nodescan

import (
	"context"
	"sort"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/stringutils"
	apiGRPC "github.com/stackrox/scanner/api/grpc"
	"github.com/stackrox/scanner/api/v1/convert"
	"github.com/stackrox/scanner/cpe/nvdtoolscache"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/kernelparser"
	"github.com/stackrox/scanner/ext/kernelparser/ubuntu"
	"github.com/stackrox/scanner/ext/versionfmt"
	v1 "github.com/stackrox/scanner/generated/scanner/api/v1"
	k8scache "github.com/stackrox/scanner/k8s/cache"
	"github.com/stackrox/scanner/pkg/version"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Service defines the node scanning service.
type Service interface {
	apiGRPC.APIService

	v1.NodeScanServiceServer
}

// NewService returns the service for node scanning
func NewService(db database.Datastore, nvdCache nvdtoolscache.Cache, k8sCache k8scache.Cache) Service {
	return &serviceImpl{
		version:  version.Version,
		db:       db,
		nvdCache: nvdCache,
		k8sCache: k8sCache,
	}
}

type serviceImpl struct {
	version  string
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
	version, err := convert.TruncateVersion(version)
	if err != nil {
		log.Warnf("unable to truncate version %v for %v:%v: %v. Skipping...", version, vendor, product, err)
		return nil, nil
	}
	nvdVulns, err := s.nvdCache.GetVulnsForComponent(vendor, product, version)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get vulns for %s:%s:%s. Skipping...", vendor, product, version)
	}

	vulns, err := convert.NVDVulns(nvdVulns)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert vulnerabilities")
	}
	return filterInvalidVulns(vulns), nil
}

func featureVersionToKernelComponent(fv database.FeatureVersion) *v1.GetNodeVulnerabilitiesResponse_KernelComponent {
	feature := fv.Feature.Name
	version := fv.Version
	if strings.HasPrefix(fv.Feature.Namespace.Name, "ubuntu") {
		version = ubuntu.StripVersionPadding(version)
	}
	return &v1.GetNodeVulnerabilitiesResponse_KernelComponent{
		Name:    feature,
		Version: version,
	}
}

func (s *serviceImpl) evaluateLinuxKernelVulns(req *v1.GetNodeVulnerabilitiesRequest) (string, []*v1.Vulnerability, *v1.GetNodeVulnerabilitiesResponse_KernelComponent, error) {
	osImage := strings.ToLower(req.GetOsImage())

	var match *kernelparser.ParseMatch
	for name, parser := range kernelparser.Parsers {
		var ok bool
		var err error
		match, ok, err = parser(s.db, req.GetKernelVersion(), osImage)
		if err != nil {
			return "", nil, nil, err
		}
		if !ok {
			continue
		}
		if match == nil {
			log.Debugf("%s %s matched %s, but no match found", osImage, req.GetKernelVersion(), name)
			return "", nil, nil, nil
		}
		break
	}

	if match == nil {
		// Did not find relevant OS-specific kernel parser.
		// Defaulting to general kernel vulns from NVD.
		vulns, err := s.getNVDVulns("linux", "linux_kernel", req.GetKernelVersion())
		return "", vulns, &v1.GetNodeVulnerabilitiesResponse_KernelComponent{
			Name:    "kernel",
			Version: req.GetKernelVersion(),
		}, err
	}

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
		return match.Namespace, nil, nil, err
	}

	vulns := make([]*v1.Vulnerability, 0, len(databaseVulns))
	for _, affected := range databaseVulns {
		metadata, err := convert.MetadataMap(affected.Metadata)
		if err != nil {
			log.Warnf("error converting metadata: %v. Skipping...", err)
			continue
		}
		if metadata == nil {
			log.Warnf("metadata is nil for %s. Skipping...", affected.Name)
			continue
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

	return match.Namespace, filterInvalidVulns(vulns), featureVersionToKernelComponent(fv), nil
}

func (s *serviceImpl) getKubernetesVuln(name, version string) ([]*v1.Vulnerability, error) {
	if name == "" || version == "" {
		return nil, nil
	}
	version, err := convert.TruncateVersion(version)
	if err != nil {
		log.Warnf("Unable to convert version of %s:%s - %v. Skipping...", name, version, err)
		return nil, nil
	}

	vulns := s.k8sCache.GetVulnsByComponent(name, version)
	converted, err := convert.K8sVulnerabilities(version, vulns)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert vulnerabilities")
	}
	return filterInvalidVulns(converted), nil
}

func normalizeDocker(version string) string {
	spl := strings.Split(version, ".")
	if len(spl) > 2 && len(spl[1]) == 1 {
		spl[1] = "0" + spl[1]
	}
	return strings.Join(spl, ".")
}

func (s *serviceImpl) getRuntimeVulns(containerRuntime *v1.GetNodeVulnerabilitiesRequest_ContainerRuntime) ([]*v1.Vulnerability, error) {
	if containerRuntime.GetName() == "" || containerRuntime.GetVersion() == "" {
		return nil, nil
	}
	switch containerRuntime.GetName() {
	case "docker":
		// Docker is in the format xx.yy.z. Sometimes, if y is a single digit, then it will not be prefixed correctly with a 0
		version := normalizeDocker(containerRuntime.GetVersion())
		return s.getNVDVulns("docker", "docker", version)
	case "crio", "cri-o":
		return s.getNVDVulns("kubernetes", "cri-o", containerRuntime.GetVersion())
	case "containerd", "runc":
		return s.getNVDVulns("linuxfoundation", containerRuntime.GetName(), containerRuntime.GetVersion())
	default:
		log.Warnf("Unsupported container runtime for node scanning: %s %s", containerRuntime.GetName(), containerRuntime.GetVersion())
	}
	return nil, nil
}

func (s *serviceImpl) GetNodeVulnerabilities(_ context.Context, req *v1.GetNodeVulnerabilitiesRequest) (*v1.GetNodeVulnerabilitiesResponse, error) {
	if stringutils.AtLeastOneEmpty(req.GetKernelVersion(), req.GetOsImage()) {
		return nil, status.Error(codes.InvalidArgument, "both os image and kernel version are required")
	}

	resp := &v1.GetNodeVulnerabilitiesResponse{
		ScannerVersion: s.version,
	}

	os, kernelVulns, kernelComponent, err := s.evaluateLinuxKernelVulns(req)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if os == "" && kernelVulns == nil && kernelComponent == nil {
		// Node's OS is unsupported, so exit early.
		resp.Notes = append(resp.Notes, v1.NodeNote_NODE_OS_UNSUPPORTED)
		return resp, nil
	}

	resp.OperatingSystem, resp.KernelVulnerabilities, resp.KernelComponent = os, kernelVulns, kernelComponent

	resp.KubeproxyVulnerabilities, err = s.getKubernetesVuln(k8scache.KubeProxy, req.GetKubeproxyVersion())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	resp.KubeletVulnerabilities, err = s.getKubernetesVuln(k8scache.Kubelet, req.GetKubeletVersion())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	resp.RuntimeVulnerabilities, err = s.getRuntimeVulns(req.GetRuntime())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return resp, nil
}

// RegisterServiceServer registers this service with the given gRPC Server.
func (s *serviceImpl) RegisterServiceServer(grpcServer *grpc.Server) {
	v1.RegisterNodeScanServiceServer(grpcServer, s)
}

// RegisterServiceHandler registers this service with the given gRPC Gateway endpoint.
func (s *serviceImpl) RegisterServiceHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return v1.RegisterNodeScanServiceHandler(ctx, mux, conn)
}
