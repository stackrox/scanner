package imagescan

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
	"github.com/stackrox/scanner/pkg/clairify/types"
	"github.com/stackrox/scanner/pkg/commonerr"
	"github.com/stackrox/scanner/pkg/rhel"
	server "github.com/stackrox/scanner/pkg/scan"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Service interface {
	apiGRPC.APIService

	v1.ImageScanServiceServer
}

// NewService returns the service for scanning
func NewService(db database.Datastore, nvdCache nvdtoolscache.Cache) Service {
	return &serviceImpl{
		db:       db,
		nvdCache: nvdCache,
	}
}

type serviceImpl struct {
	db       database.Datastore
	nvdCache nvdtoolscache.Cache
}

func (s *serviceImpl) GetLanguageLevelComponents(ctx context.Context, req *v1.GetLanguageLevelComponentsRequest) (*v1.GetLanguageLevelComponentsResponse, error) {
	layerName, err := s.getLayerNameFromImageSpec(req.GetImageSpec(), req.GetUncertifiedRHEL())
	if err != nil {
		return nil, err
	}
	if req.GetUncertifiedRHEL() {
		logrus.Debugf("Getting language level components for uncertified layer %s", layerName)
	}
	components, err := s.db.GetLayerLanguageComponents(layerName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to retrieve components from DB: %v", err)
	}
	if req.GetUncertifiedRHEL() {
		for _, component := range components {
			component.Layer = rhel.GetOriginalLayerName(component.Layer)
		}
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

	if req.GetUncertifiedRHEL() {
		logrus.Debugf("Triggering uncertified image scan for %s", image)
	}

	digest, err := server.ProcessImage(s.db, image, reg.GetUrl(), reg.GetUsername(), reg.GetPassword(), reg.GetInsecure(), req.GetUncertifiedRHEL())
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

func (s *serviceImpl) getLayer(layerName string, uncertifiedRHEL bool) (*v1.GetImageScanResponse, error) {
	if uncertifiedRHEL {
		layerName = rhel.GetUncertifiedLayerName(layerName)
	}
	dbLayer, err := s.db.FindLayer(layerName, true, true)
	if err == commonerr.ErrNotFound {
		return nil, status.Errorf(codes.NotFound, "Could not find Clair layer %q", layerName)
	}
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// This endpoint is not used, so not going to bother with notes until they are necessary.
	layer, _, err := apiV1.LayerFromDatabaseModel(s.db, dbLayer, true, true, uncertifiedRHEL)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	features, err := convertFeatures(layer.Features)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error converting features: %v", err)
	}

	return &v1.GetImageScanResponse{
		Status: v1.ScanStatus_SUCCEEDED,
		Image: &v1.Image{
			Features: features,
		},
	}, nil
}

func (s *serviceImpl) getLayerNameFromImageSpec(imgSpec *v1.ImageSpec, uncertifiedRHEL bool) (string, error) {
	if stringutils.AllEmpty(imgSpec.GetImage(), imgSpec.GetDigest()) {
		return "", status.Error(codes.InvalidArgument, "either image or digest must be specified")
	}

	var layerFetcher func(layer string, uncertifiedRHEL bool) (string, bool, error)
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
	layerName, exists, err := layerFetcher(argument, uncertifiedRHEL)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", status.Errorf(codes.NotFound, "image with reference %q not found", argument)
	}
	if uncertifiedRHEL {
		layerName = rhel.GetUncertifiedLayerName(layerName)
	}
	return layerName, nil
}

func (s *serviceImpl) GetImageScan(ctx context.Context, req *v1.GetImageScanRequest) (*v1.GetImageScanResponse, error) {
	layerName, err := s.getLayerNameFromImageSpec(req.GetImageSpec(), req.GetUncertifiedRHEL())
	if err != nil {
		return nil, err
	}
	if req.GetUncertifiedRHEL() {
		logrus.Debugf("Getting image scan for uncertified image layer %s", layerName)
	}
	return s.getLayer(layerName, req.GetUncertifiedRHEL())
}

// RegisterServiceServer registers this service with the given gRPC Server.
func (s *serviceImpl) RegisterServiceServer(grpcServer *grpc.Server) {
	v1.RegisterImageScanServiceServer(grpcServer, s)
}

// RegisterServiceHandler registers this service with the given gRPC Gateway endpoint.
func (s *serviceImpl) RegisterServiceHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return v1.RegisterImageScanServiceHandler(ctx, mux, conn)
}
