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
	apiV1 "github.com/stackrox/scanner/api/v1"
	"github.com/stackrox/scanner/api/v1/common"
	"github.com/stackrox/scanner/api/v1/convert"
	"github.com/stackrox/scanner/api/v1/features"
	"github.com/stackrox/scanner/cpe/nvdtoolscache"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/kernelparser"
	"github.com/stackrox/scanner/ext/kernelparser/ubuntu"
	"github.com/stackrox/scanner/ext/versionfmt"
	v1 "github.com/stackrox/scanner/generated/scanner/api/v1"
	k8scache "github.com/stackrox/scanner/k8s/cache"
	featureFlags "github.com/stackrox/scanner/pkg/features"
	"github.com/stackrox/scanner/pkg/repo2cpe"
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
func NewService(db database.Datastore, nvdCache nvdtoolscache.Cache, k8sCache k8scache.Cache, repoToCPE *repo2cpe.Mapping) Service {
	return &serviceImpl{
		version:   version.Version,
		db:        db,
		nvdCache:  nvdCache,
		k8sCache:  k8sCache,
		repoToCPE: repoToCPE,
	}
}

type serviceImpl struct {
	v1.UnimplementedNodeScanServiceServer

	version   string
	db        database.Datastore
	nvdCache  nvdtoolscache.Cache
	k8sCache  k8scache.Cache
	repoToCPE *repo2cpe.Mapping
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

// parseLinuxKernel parses the linux kernel based on the given osImage and kernelVersion.
// The returned kernel may be nil even without error if it could not be determined.
func (s *serviceImpl) parseLinuxKernel(osImage, kernelVersion string) (*kernelparser.ParseMatch, error) {
	osImageLower := strings.ToLower(osImage)

	for name, parser := range kernelparser.Parsers {
		match, err := parser(s.db, kernelVersion, osImageLower)
		switch err {
		case nil:
			// Found a match.
			return match, nil
		case kernelparser.ErrKernelUnrecognized:
			// This parser did not recognize the kernel. Try another one.
			continue
		case kernelparser.ErrKernelUnsupported:
			log.Debugf("%s parser found unsupported kernel: %s %s", name, osImage, kernelVersion)
		case kernelparser.ErrNodeUnsupported:
			log.Debugf("%s parser found unsupported node: %s %s", name, osImage, kernelVersion)
		default:
			log.Warnf("Unable to parse kernel: %v", err)
		}

		return nil, err
	}

	return nil, nil
}

func (s *serviceImpl) evaluateLinuxKernelVulns(req *v1.GetNodeVulnerabilitiesRequest) (string, []*v1.Vulnerability, *v1.GetNodeVulnerabilitiesResponse_KernelComponent, error) {
	kernelVersion := req.GetKernelVersion()

	match, err := s.parseLinuxKernel(req.GetOsImage(), kernelVersion)
	if err != nil {
		return "", nil, nil, err
	}

	if match == nil {
		log.Debugf("Did not find relevant OS-specific kernel parser for %s %s; defaulting to generic kernel vulns from NVD", req.GetOsImage(), kernelVersion)
		vulns, err := s.getNVDVulns("linux", "linux_kernel", kernelVersion)
		return "", vulns, &v1.GetNodeVulnerabilitiesResponse_KernelComponent{
			Name:    "kernel",
			Version: kernelVersion,
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
			Severity:    string(convert.DatabaseSeverityToSeverity(affected.Severity)),
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

func isRHCOS(ns string) bool {
	return strings.HasPrefix(ns, "rhcos")
}

func (s *serviceImpl) GetNodeVulnerabilities(ctx context.Context, req *v1.GetNodeVulnerabilitiesRequest) (*v1.GetNodeVulnerabilitiesResponse, error) {
	resp := &v1.GetNodeVulnerabilitiesResponse{
		ScannerVersion: s.version,
	}
	// If NodeInventory is empty `req.GetComponents() == nil` then fallback to v1 scanning
	if req.GetComponents() == nil || !featureFlags.RHCOSNodeScanning.Enabled() {
		return s.getNodeVulnerabilitiesLegacy(ctx, req, resp)
	}

	if !isRHCOS(req.GetComponents().GetNamespace()) {
		// Non-RHCOS system detecetd, we can provide list of pkgs but cannot scan them, thus a node to inform the user
		resp.NodeNotes = append(resp.GetNodeNotes(), v1.NodeNote_NODE_UNSUPPORTED)
	}

	var err error
	if resp.Features, err = s.getNodeInventoryVulns(req.GetComponents(), common.HasUncertifiedRHEL(req.GetNotes())); err != nil {
		log.Warnf("Scanning node inventory failed: %v", err)
		return nil, err
	}
	return resp, nil
}

func (s *serviceImpl) getNodeVulnerabilitiesLegacy(_ context.Context, req *v1.GetNodeVulnerabilitiesRequest, resp *v1.GetNodeVulnerabilitiesResponse) (*v1.GetNodeVulnerabilitiesResponse, error) {
	if stringutils.AtLeastOneEmpty(req.GetKernelVersion(), req.GetOsImage()) {
		return nil, status.Error(codes.InvalidArgument, "both os image and kernel version are required")
	}

	var err error
	resp.OperatingSystem, resp.KernelVulnerabilities, resp.KernelComponent, err = s.evaluateLinuxKernelVulns(req)
	switch err {
	case nil: // Normal
	case kernelparser.ErrNodeUnsupported:
		// The node is unsupported, exit early.
		resp.NodeNotes = append(resp.GetNodeNotes(), v1.NodeNote_NODE_UNSUPPORTED)
		return resp, nil
	case kernelparser.ErrKernelUnsupported:
		resp.NodeNotes = append(resp.GetNodeNotes(), v1.NodeNote_NODE_KERNEL_UNSUPPORTED)
	default:
		return nil, status.Error(codes.Internal, err.Error())
	}

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

func (s *serviceImpl) getNodeInventoryVulns(components *v1.Components, isUncertifiedRHEL bool) ([]*v1.Feature, error) {
	log.Debugf("Scanning NodeInventory")
	// Convert content sets to CPEs
	cpes := s.repoToCPE.Get(components.GetRhelContentSets())
	log.Debugf("Converted content sets '%v' to CPEs '%v'", components.GetRhelContentSets(), cpes)
	for _, comp := range components.GetRhelComponents() {
		// TODO(ROX-14414): Handle situation when CPEs are provided in parallel to content sets
		// Overwrite any potential CPEs and stick to content sets to sanitize the API input
		comp.Cpes = cpes
	}
	layer, err := apiV1.GetVulnerabilitiesForComponents(s.db, components, isUncertifiedRHEL)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	log.Infof("Matched vulnerabilities on %d RHEL components in node inventory", len(components.GetRhelComponents()))
	return features.ConvertFeatures(layer.Features), nil
}

// RegisterServiceServer registers this service with the given gRPC Server.
func (s *serviceImpl) RegisterServiceServer(grpcServer *grpc.Server) {
	v1.RegisterNodeScanServiceServer(grpcServer, s)
}

// RegisterServiceHandler registers this service with the given gRPC Gateway endpoint.
func (s *serviceImpl) RegisterServiceHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return v1.RegisterNodeScanServiceHandler(ctx, mux, conn)
}
