package imagescan

import (
	"context"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/stringutils"
	apiGRPC "github.com/stackrox/scanner/api/grpc"
	apiV1 "github.com/stackrox/scanner/api/v1"
	"github.com/stackrox/scanner/api/v1/common"
	"github.com/stackrox/scanner/cpe/nvdtoolscache"
	"github.com/stackrox/scanner/database"
	v1 "github.com/stackrox/scanner/generated/scanner/api/v1"
	"github.com/stackrox/scanner/pkg/clairify/types"
	"github.com/stackrox/scanner/pkg/commonerr"
	server "github.com/stackrox/scanner/pkg/scan"
	"github.com/stackrox/scanner/pkg/version"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Service defines the image scanning service.
type Service interface {
	apiGRPC.APIService

	v1.ImageScanServiceServer
}

// NewService returns the service for image scanning
func NewService(db database.Datastore, nvdCache nvdtoolscache.Cache) Service {
	return &serviceImpl{
		version:  version.Version,
		db:       db,
		nvdCache: nvdCache,
	}
}

type serviceImpl struct {
	v1.UnimplementedImageScanServiceServer

	version  string
	db       database.Datastore
	nvdCache nvdtoolscache.Cache
}

func (s *serviceImpl) ScanImage(_ context.Context, req *v1.ScanImageRequest) (*v1.ScanImageResponse, error) {
	image, err := types.GenerateImageFromString(req.GetImage())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "could not parse image %q", req.GetImage())
	}

	reg := req.GetRegistry()

	digest, err := server.ProcessImage(s.db, image, reg.GetUrl(), reg.GetUsername(), reg.GetPassword(), reg.GetInsecure(), req.GetUncertifiedRHEL())
	if err != nil {
		return nil, err
	}

	return &v1.ScanImageResponse{
		ScannerVersion: s.version,
		Status:         v1.ScanStatus_SUCCEEDED,
		Image: &v1.ImageSpec{
			Digest: digest,
			Image:  image.TaggedName(),
		},
	}, nil
}

func (s *serviceImpl) GetImageScan(_ context.Context, req *v1.GetImageScanRequest) (*v1.GetImageScanResponse, error) {
	opts := &database.DatastoreOptions{
		WithFeatures:        true,
		WithVulnerabilities: true,
		UncertifiedRHEL:     req.GetUncertifiedRHEL(),
	}

	dbLayer, lineage, err := s.getLayer(req, opts)
	if err != nil {
		return nil, err
	}

	depMap := common.GetDepMap(dbLayer.Features)
	layer, notes, err := apiV1.LayerFromDatabaseModel(s.db, *dbLayer, lineage, depMap, opts)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &v1.GetImageScanResponse{
		ScannerVersion: s.version,
		Status:         v1.ScanStatus_SUCCEEDED,
		Image: &v1.Image{
			Namespace: layer.NamespaceName,
			Features:  ConvertFeatures(layer.Features),
		},
		Notes: convertNotes(notes),
	}, nil
}

func (s *serviceImpl) getLayer(req imageRequest, opts *database.DatastoreOptions) (*database.Layer, string, error) {
	layerName, lineage, err := s.getLayerNameFromImageReq(req)
	if err != nil {
		return nil, "", err
	}

	dbLayer, err := s.db.FindLayer(layerName, lineage, opts)
	if err == commonerr.ErrNotFound {
		return nil, "", status.Errorf(codes.NotFound, "Could not find layer %q", layerName)
	} else if err != nil {
		return nil, "", status.Error(codes.Internal, err.Error())
	}

	return &dbLayer, lineage, nil
}

func (s *serviceImpl) getLayerNameFromImageReq(req imageRequest) (string, string, error) {
	imgSpec := req.GetImageSpec()

	if stringutils.AllEmpty(imgSpec.GetImage(), imgSpec.GetDigest()) {
		return "", "", status.Error(codes.InvalidArgument, "either image or digest must be specified")
	}

	var layerFetcher func(s string, opts *database.DatastoreOptions) (string, string, bool, error)
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
	layerName, lineage, exists, err := layerFetcher(argument, &database.DatastoreOptions{
		UncertifiedRHEL: req.GetUncertifiedRHEL(),
	})
	if err != nil {
		return "", "", err
	}
	if !exists {
		return "", "", status.Errorf(codes.NotFound, "image with reference %q not found", argument)
	}
	return layerName, lineage, nil
}

func (s *serviceImpl) GetImageComponents(ctx context.Context, req *v1.GetImageComponentsRequest) (*v1.GetImageComponentsResponse, error) {
	image := req.GetImage()
	logrus.Infof("Analyzing image components for %s", image)

	// Attempt to get image results assuming the image is within RHEL Certification scope (or is a non-RHEL image).
	imgComponents, err := s.getImageComponents(ctx, req, false)
	if err != nil {
		return nil, err
	}
	for _, note := range imgComponents.Notes {
		if note == apiV1.CertifiedRHELScanUnavailable {
			logrus.Infof("%s is a RHEL-based image not within certification scope. Trying again...", image)

			// Image is RHEL, but not within Certification scope. Try again...
			imgComponents, err = s.getImageComponents(ctx, req, true)
			if err != nil {
				return nil, err
			}

			break
		}
	}

	logrus.Infof("Done analyzing components for %s", image)

	return &v1.GetImageComponentsResponse{
		ScannerVersion: s.version,
		Status:         v1.ScanStatus_SUCCEEDED,
		Components:     convertImageComponents(imgComponents),
		Notes:          convertNotes(imgComponents.Notes),
	}, nil
}

func (s *serviceImpl) getImageComponents(ctx context.Context, req *v1.GetImageComponentsRequest, uncertifiedRHEL bool) (*apiV1.ComponentsEnvelope, error) {
	imageScan, err := s.ScanImage(ctx, &v1.ScanImageRequest{
		Image:           req.GetImage(),
		Registry:        req.GetRegistry(),
		UncertifiedRHEL: uncertifiedRHEL,
	})
	if err != nil {
		return nil, err
	}

	dbLayer, lineage, err := s.getLayer(&imageReq{
		imageSpec:       imageScan.GetImage(),
		uncertifiedRHEL: uncertifiedRHEL,
	}, &database.DatastoreOptions{
		WithFeatures:    true,
		UncertifiedRHEL: uncertifiedRHEL,
	})
	if err != nil {
		return nil, err
	}

	components, err := apiV1.ComponentsFromDatabaseModel(s.db, dbLayer, lineage, uncertifiedRHEL)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return components, nil
}

func (s *serviceImpl) GetImageVulnerabilities(_ context.Context, req *v1.GetImageVulnerabilitiesRequest) (*v1.GetImageVulnerabilitiesResponse, error) {
	layer, err := apiV1.GetVulnerabilitiesForComponents(s.db, req.GetComponents(), hasUncertifiedRHEL(req.GetNotes()))
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &v1.GetImageVulnerabilitiesResponse{
		ScannerVersion: s.version,
		Status:         v1.ScanStatus_SUCCEEDED,
		Image: &v1.Image{
			Namespace: layer.NamespaceName,
			Features:  ConvertFeatures(layer.Features),
		},
	}, nil
}

func hasUncertifiedRHEL(notes []v1.Note) bool {
	for _, note := range notes {
		if note == v1.Note_CERTIFIED_RHEL_SCAN_UNAVAILABLE {
			return true
		}
	}

	return false
}

func (s *serviceImpl) GetLanguageLevelComponents(_ context.Context, req *v1.GetLanguageLevelComponentsRequest) (*v1.GetLanguageLevelComponentsResponse, error) {
	layerName, lineage, err := s.getLayerNameFromImageReq(req)
	if err != nil {
		return nil, err
	}
	components, err := s.db.GetLayerLanguageComponents(layerName, lineage, &database.DatastoreOptions{
		UncertifiedRHEL: req.GetUncertifiedRHEL(),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to retrieve components from DB: %v", err)
	}
	return &v1.GetLanguageLevelComponentsResponse{
		ScannerVersion:    s.version,
		LayerToComponents: convertLanguageLevelComponents(components),
	}, nil
}

// RegisterServiceServer registers this service with the given gRPC Server.
func (s *serviceImpl) RegisterServiceServer(grpcServer *grpc.Server) {
	v1.RegisterImageScanServiceServer(grpcServer, s)
}

// RegisterServiceHandler registers this service with the given gRPC Gateway endpoint.
func (s *serviceImpl) RegisterServiceHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return v1.RegisterImageScanServiceHandler(ctx, mux, conn)
}
