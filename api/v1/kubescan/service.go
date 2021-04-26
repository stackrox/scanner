package kubescan

import (
	"context"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	apiGRPC "github.com/stackrox/scanner/api/grpc"
	"github.com/stackrox/scanner/api/v1/convert"
	v1 "github.com/stackrox/scanner/generated/shared/api/v1"
	k8scache "github.com/stackrox/scanner/k8s/cache"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Service interface {
	apiGRPC.APIService

	v1.KubeScanServiceServer
}

// NewService returns the service for scanning
func NewService(k8sCache k8scache.Cache) Service {
	return &serviceImpl{
		k8sCache: k8sCache,
	}
}

type serviceImpl struct {
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

	return &resp, nil
}

// RegisterServiceServer registers this service with the given gRPC Server.
func (s *serviceImpl) RegisterServiceServer(grpcServer *grpc.Server) {
	v1.RegisterKubeScanServiceServer(grpcServer, s)
}

// RegisterServiceHandler registers this service with the given gRPC Gateway endpoint.
func (s *serviceImpl) RegisterServiceHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return v1.RegisterKubeScanServiceHandler(ctx, mux, conn)
}
