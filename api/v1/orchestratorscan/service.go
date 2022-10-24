package orchestratorscan

import (
	"context"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	rpmVersion "github.com/knqyf263/go-rpm-version"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	apiGRPC "github.com/stackrox/scanner/api/grpc"
	apiV1 "github.com/stackrox/scanner/api/v1"
	"github.com/stackrox/scanner/api/v1/convert"
	"github.com/stackrox/scanner/database"
	v1 "github.com/stackrox/scanner/generated/scanner/api/v1"
	k8scache "github.com/stackrox/scanner/k8s/cache"
	"github.com/stackrox/scanner/pkg/version"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Service defines an orchestrator scanning service.
type Service interface {
	apiGRPC.APIService

	v1.OrchestratorScanServiceServer
}

// NewService returns the service for scanning
func NewService(db database.Datastore, k8sCache k8scache.Cache) Service {
	return &serviceImpl{
		version:  version.Version,
		db:       db,
		k8sCache: k8sCache,
	}
}

type serviceImpl struct {
	v1.UnimplementedOrchestratorScanServiceServer

	version  string
	db       database.Datastore
	k8sCache k8scache.Cache
}

func filterInvalidVulns(vulns []*v1.Vulnerability) []*v1.Vulnerability {
	filteredVulns := make([]*v1.Vulnerability, 0, len(vulns))
	for _, v := range vulns {
		if v.GetMetadataV2().GetCvssV2() == nil && v.GetMetadataV2().GetCvssV3() == nil {
			continue
		}
		filteredVulns = append(filteredVulns, v)
	}
	return filteredVulns
}

func (s *serviceImpl) getKubernetesVuln(name, version string) ([]*v1.Vulnerability, error) {
	if version == "" {
		return nil, errors.New("Can't get vulnerabilities for empty version.")
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

// GetKubeVulnerabilities returns Kubernetes vulnerabilities for requested Kubernetes version.
func (s *serviceImpl) GetKubeVulnerabilities(_ context.Context, req *v1.GetKubeVulnerabilitiesRequest) (*v1.GetKubeVulnerabilitiesResponse, error) {
	var err error
	resp := &v1.GetKubeVulnerabilitiesResponse{
		ScannerVersion: s.version,
	}

	resp.AggregatorVulnerabilities, err = s.getKubernetesVuln(k8scache.KubeAggregator, req.GetKubernetesVersion())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	resp.ApiserverVulnerabilities, err = s.getKubernetesVuln(k8scache.KubeAPIServer, req.GetKubernetesVersion())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	resp.ControllerManagerVulnerabilities, err = s.getKubernetesVuln(k8scache.KubeControllerManager, req.GetKubernetesVersion())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	resp.SchedulerVulnerabilities, err = s.getKubernetesVuln(k8scache.KubeScheduler, req.GetKubernetesVersion())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	resp.GenericVulnerabilities, err = s.getKubernetesVuln(k8scache.Generic, req.GetKubernetesVersion())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return resp, nil
}

func (s *serviceImpl) getOpenShiftVulns(version *openShiftVersion) ([]*database.RHELv2Vulnerability, error) {
	pkg := &database.RHELv2Package{
		Name: version.CreatePkgName(),
	}

	records := []*database.RHELv2Record{
		{
			Pkg: pkg,
			CPE: version.CreateCPE(),
		},
	}

	vulnsMap, err := s.db.GetRHELv2Vulnerabilities(records)
	if err != nil {
		return nil, err
	}

	if vulns, ok := vulnsMap[pkg.ID]; ok {
		return vulns, nil
	}
	return nil, errors.Wrap(err, "failed to fetch vulns")
}

// GetOpenShiftVulnerabilities returns Openshift vulnerabilities for requested Openshift version.
func (s *serviceImpl) GetOpenShiftVulnerabilities(_ context.Context, req *v1.GetOpenShiftVulnerabilitiesRequest) (*v1.GetOpenShiftVulnerabilitiesResponse, error) {
	version, err := newOpenShiftVersion(req.OpenShiftVersion)
	if err != nil {
		return nil, err
	}

	vulns, err := s.getOpenShiftVulns(version)
	if err != nil {
		return nil, err
	}

	resp := &v1.GetOpenShiftVulnerabilitiesResponse{
		ScannerVersion: s.version,
	}
	for _, vuln := range vulns {
		if len(vuln.Packages) != 1 {
			log.Warnf("unexpected number of packages for vuln %q (%d != %d); Skipping...", vuln.Name, len(vuln.Packages), 1)
			continue
		}
		vulnPkg := vuln.Packages[0]

		affectedArch := vulnPkg.ArchOperation.Cmp("x86_64", vulnPkg.Arch)
		if !affectedArch {
			log.Warnf("vuln %s is for arch %v %s, Skipping ...", vuln.Name, vulnPkg.ArchOperation, vulnPkg.Arch)
			continue
		}

		// Skip fixed vulns.
		fixedBy, err := version.GetFixedVersion(vulnPkg.FixedInVersion, vuln.Title)
		if err != nil {
			// Skip it. The vuln has a fixedBy version, but we cannot extract it.
			log.Errorf("cannot get fix version for vuln %s: %v, Skipping ...", vuln.Name, err)
			continue
		}

		if fixedBy != "" && !version.LessThan(rpmVersion.NewVersion(fixedBy)) {
			log.Debugf("vuln %s has been fixed: %s, Skipping", vuln.Name, fixedBy)
			continue
		}
		v1Vuln := apiV1.RHELv2ToVulnerability(vuln, "")
		metadata, err := convert.MetadataMap(v1Vuln.Metadata)
		if err != nil {
			log.Errorf("error converting metadata for %s: %v. Skipping...", vuln.Name, err)
			continue
		}
		if metadata == nil {
			log.Warnf("metadata is nil for %s; Skipping...", vuln.Name)
			continue
		}

		resp.Vulnerabilities = append(resp.Vulnerabilities, &v1.Vulnerability{
			Name:        v1Vuln.Name,
			Description: v1Vuln.Description,
			Link:        v1Vuln.Link,
			MetadataV2:  metadata,
			FixedBy:     fixedBy,
			Severity:    vuln.Severity,
		})
	}
	resp.Vulnerabilities = filterInvalidVulns(resp.Vulnerabilities)
	return resp, err
}

// RegisterServiceServer registers this service with the given gRPC Server.
func (s *serviceImpl) RegisterServiceServer(grpcServer *grpc.Server) {
	v1.RegisterOrchestratorScanServiceServer(grpcServer, s)
}

// RegisterServiceHandler registers this service with the given gRPC Gateway endpoint.
func (s *serviceImpl) RegisterServiceHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return v1.RegisterOrchestratorScanServiceHandler(ctx, mux, conn)
}
