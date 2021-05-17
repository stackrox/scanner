package orchestratorscan

import (
	"context"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	apiGRPC "github.com/stackrox/scanner/api/grpc"
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

// GetOpenShiftVulnerabilities returns Openshift vulnerabilities for requested Openshift version.
func (s *serviceImpl) GetOpenShiftVulnerabilities(_ context.Context, req *v1.GetOpenShiftVulnerabilitiesRequest) (*v1.GetOpenShiftVulnerabilitiesResponse, error) {
	var err error
	var resp v1.GetOpenShiftVulnerabilitiesResponse
	version, err := newVersion(req.OpenShiftVersion)
	if err != nil {
		return nil, err
	}
	_ = &database.RHELv2Package{ // pkg
		Name:    "openshift-hyperkube",
		Version: req.OpenShiftVersion,
		Model:   database.Model{ID: 1},
	}

	records := []*database.RHELv2Record{
		{
			Pkg: &database.RHELv2Package{
				Name:    "openshift-hyperkube",
				Version: req.OpenShiftVersion,
			},
			CPE: version.GetCPE(),
		},
	}
	_, err = s.db.GetRHELv2Vulnerabilities(records) // vulns
	if err != nil {
		return nil, err
	}

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
