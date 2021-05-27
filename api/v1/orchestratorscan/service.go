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
	v1 "github.com/stackrox/scanner/generated/shared/api/v1"
	k8scache "github.com/stackrox/scanner/k8s/cache"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Service interface {
	apiGRPC.APIService

	v1.OrchestratorScanServiceServer
}

// NewService returns the service for scanning
func NewService(db database.Datastore, k8sCache k8scache.Cache) Service {
	return &serviceImpl{
		db:       db,
		k8sCache: k8sCache,
	}
}

type serviceImpl struct {
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
	var resp v1.GetKubeVulnerabilitiesResponse

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

	return &resp, nil
}

func (s *serviceImpl) getOpenShiftVulns(version *openShiftVersion) ([]*database.RHELv2Vulnerability, error) {
	pkg := &database.RHELv2Package{
		Name:  version.CreatePkgName(),
		Model: database.Model{ID: 1},
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
	return nil, errors.Errorf("failed to fetch vulns, %v", err)
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

	var resp v1.GetOpenShiftVulnerabilitiesResponse
	for _, vuln := range vulns {
		if len(vuln.PackageInfos) != 1 {
			log.Warnf("unexpected number of package infos for vuln %q (%d != %d); Skipping...", vuln.Name, len(vuln.PackageInfos), 1)
			continue
		}
		vulnPkgInfo := vuln.PackageInfos[0]

		if len(vulnPkgInfo.Packages) != 1 {
			log.Warnf("Unexpected number of packages for vuln %q (%d != %d); Skipping...", vuln.Name, len(vulnPkgInfo.Packages), 1)
			continue
		}

		vulnPkg := vulnPkgInfo.Packages[0]
		affectedArch := vulnPkgInfo.ArchOperation.Cmp("x86_64", vulnPkg.Arch)
		if !affectedArch {
			log.Warnf("cannot get fixed by for vuln %s: %v, Skipping ...", vuln.Name, err)
			continue
		}

		// Skip fixed vulns.
		fixedBy, err := version.GetFixedVersion(vulnPkgInfo.FixedInVersion, vuln.Title)
		if err != nil {
			// Skip it. The vuln has a fixedBy version but we cannot extract it.
			log.Warnf("cannot get fixed by for vuln %s: %v, Skipping ...", vuln.Name, err)
			continue
		}

		if fixedBy != "" && !version.LessThan(rpmVersion.NewVersion(fixedBy)) {
			log.Debugf("vuln %s has been fixed: %s, Skipping", vuln.Name, vulnPkgInfo.FixedInVersion)
			continue
		}
		v1Vuln := apiV1.Rhelv2ToVulnerability(vuln, "")
		metadata, err := convert.MetadataMap(v1Vuln.Metadata)
		if err != nil {
			log.Warnf("error converting metadata for %s: %v. Skipping...", vuln.Name, err)
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
	return &resp, err
}

// RegisterServiceServer registers this service with the given gRPC Server.
func (s *serviceImpl) RegisterServiceServer(grpcServer *grpc.Server) {
	v1.RegisterOrchestratorScanServiceServer(grpcServer, s)
}

// RegisterServiceHandler registers this service with the given gRPC Gateway endpoint.
func (s *serviceImpl) RegisterServiceHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return v1.RegisterOrchestratorScanServiceHandler(ctx, mux, conn)
}
