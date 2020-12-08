package scan

import (
	"context"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/stringutils"
	apiGRPC "github.com/stackrox/scanner/api/grpc"
	apiV1 "github.com/stackrox/scanner/api/v1"
	"github.com/stackrox/scanner/cpe/nvdtoolscache"
	"github.com/stackrox/scanner/database"
	v1 "github.com/stackrox/scanner/generated/shared/api/v1"
	k8scache "github.com/stackrox/scanner/k8s/cache"
	"github.com/stackrox/scanner/pkg/clairify/types"
	"github.com/stackrox/scanner/pkg/commonerr"
	server "github.com/stackrox/scanner/pkg/scan"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Service interface {
	apiGRPC.APIService

	v1.ScanServiceServer
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

func (s *serviceImpl) GetVulnerabilities(_ context.Context, req *v1.GetVulnerabilitiesRequest) (*v1.GetVulnerabilitiesResponse, error) {
	resp := make([]*v1.ComponentWithVulns, 0, len(req.GetComponents()))

	k8sVulns := make(map[v1.Component_K8SComponent]bool)
	appVulns := make(map[v1.Component_AppComponent]bool)
	for _, component := range req.GetComponents() {
		switch typ := component.GetComponent().(type) {
		case *v1.Component_K8SComponent:
			c := typ.K8SComponent.Component
			version := typ.K8SComponent.Version

			component := v1.Component_K8SComponent{
				K8SComponent: &v1.KubernetesComponent{
					Component: c,
					Version:   version,
				},
			}
			if _, exists := k8sVulns[component]; exists {
				continue
			}

			vulns := s.k8sCache.GetVulnsByComponent(c, version)
			converted, err := convertK8sVulnerabilities(version, vulns)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "failed to convert vulnerabilities: %v", err)
			}

			k8sVulns[component] = true
			resp = append(resp, &v1.ComponentWithVulns{
				Component: &v1.Component{
					Component: &component,
				},
				Vulnerabilities: converted,
			})
		case *v1.Component_AppComponent:
			vendor := typ.AppComponent.Vendor
			product := typ.AppComponent.Product
			version := typ.AppComponent.Version

			component := v1.Component_AppComponent{
				AppComponent: &v1.ApplicationComponent{
					Vendor:  vendor,
					Product: product,
					Version: version,
				},
			}
			if _, exists := appVulns[component]; exists {
				continue
			}

			nvdVulns, err := s.nvdCache.GetVulnsForComponent(vendor, product, version)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "failed to get vulns for product %s: %v", typ.AppComponent.Product, err)
			}

			vulns, err := convertNVDVulns(nvdVulns)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "failed to convert vulnerabilities: %v", err)
			}

			appVulns[component] = true
			resp = append(resp, &v1.ComponentWithVulns{
				Component: &v1.Component{
					Component: &component,
				},
				Vulnerabilities: vulns,
			})
		case nil:
			return nil, status.Error(codes.InvalidArgument, "component request must be set")
		default:
			return nil, status.Errorf(codes.InvalidArgument, "component request has unexpected type %T", typ)
		}
	}

	return &v1.GetVulnerabilitiesResponse{
		VulnerabilitiesByComponent: resp,
	}, nil
}

func (s *serviceImpl) GetLanguageLevelComponents(ctx context.Context, req *v1.GetLanguageLevelComponentsRequest) (*v1.GetLanguageLevelComponentsResponse, error) {
	layerName, err := s.getLayerNameFromImageSpec(req.GetImageSpec())
	if err != nil {
		return nil, err
	}
	components, err := s.db.GetLayerLanguageComponents(layerName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to retrieve components from DB: %v", err)
	}
	return &v1.GetLanguageLevelComponentsResponse{
		LayerToComponents: convertComponents(components),
	}, nil
}

func (s *serviceImpl) ScanImage(ctx context.Context, req *v1.ScanImageRequest) (*v1.ScanImageResponse, error) {
	image, err := types.GenerateImageFromString(req.GetImage())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "could not parse image %q", req.GetImage())
	}

	reg := req.GetRegistry()

	digest, err := server.ProcessImage(s.db, image, reg.GetUrl(), reg.GetUsername(), reg.GetPassword(), reg.GetInsecure())
	if err != nil {
		return nil, err
	}

	return &v1.ScanImageResponse{
		Status: v1.ScanStatus_SUCCEEDED,
		Image: &v1.ImageSpec{
			Digest: digest,
			Image:  image.TaggedName(),
		},
	}, nil
}

func (s *serviceImpl) getLayer(layerName string) (*v1.GetScanResponse, error) {
	dbLayer, err := s.db.FindLayer(layerName, true, true)
	if err == commonerr.ErrNotFound {
		return nil, status.Errorf(codes.NotFound, "Could not find Clair layer %q", layerName)
	} else if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// This endpoint is not used, so not going to bother with notes until they are necessary.
	layer, _, err := apiV1.LayerFromDatabaseModel(s.db, dbLayer, true, true)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	features, err := convertFeatures(layer.Features)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error converting features: %v", err)
	}

	return &v1.GetScanResponse{
		Status: v1.ScanStatus_SUCCEEDED,
		Image: &v1.Image{
			Features: features,
		},
	}, nil
}

func (s *serviceImpl) getLayerNameFromImageSpec(imgSpec *v1.ImageSpec) (string, error) {
	if stringutils.AllEmpty(imgSpec.GetImage(), imgSpec.GetDigest()) {
		return "", status.Error(codes.InvalidArgument, "either image or digest must be specified")
	}

	var layerFetcher func(s string) (string, bool, error)
	var argument string
	if digest := imgSpec.GetDigest(); digest != "" {
		logrus.Debugf("Getting layer SHA by digest %s", digest)
		argument = digest
		layerFetcher = s.db.GetLayerBySHA
	} else {
		logrus.Debugf("Getting layer SHA by image %s", imgSpec.GetImage())
		argument = imgSpec.GetImage()
		layerFetcher = s.db.GetLayerByName
	}
	layerName, exists, err := layerFetcher(argument)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", status.Errorf(codes.NotFound, "image with reference %q not found", argument)
	}
	return layerName, nil
}

func (s *serviceImpl) GetScan(ctx context.Context, req *v1.GetScanRequest) (*v1.GetScanResponse, error) {
	layerName, err := s.getLayerNameFromImageSpec(req.GetImageSpec())
	if err != nil {
		return nil, err
	}
	return s.getLayer(layerName)
}

// RegisterServiceServer registers this service with the given gRPC Server.
func (s *serviceImpl) RegisterServiceServer(grpcServer *grpc.Server) {
	v1.RegisterScanServiceServer(grpcServer, s)
}

// RegisterServiceHandler registers this service with the given gRPC Gateway endpoint.
func (s *serviceImpl) RegisterServiceHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return v1.RegisterScanServiceHandler(ctx, mux, conn)
}
