package scan

import (
	"context"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/stringutils"
	apiGRPC "github.com/stackrox/scanner/api/grpc"
	apiV1 "github.com/stackrox/scanner/api/v1"
	"github.com/stackrox/scanner/database"
	v1 "github.com/stackrox/scanner/generated/api/v1"
	"github.com/stackrox/scanner/pkg/clairify/types"
	"github.com/stackrox/scanner/pkg/commonerr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Service interface {
	apiGRPC.APIService

	v1.ScanServiceServer
}

// NewScanService returns the service for scanning
func NewScanService(db database.Datastore) Service {
	return &serviceImpl{
		db: db,
	}
}

// serviceImpl provides APIs for alerts.
type serviceImpl struct {
	db database.Datastore
}

func (s *serviceImpl) ScanImage(ctx context.Context, req *v1.ScanImageRequest) (*v1.ScanImageResponse, error) {
	image, err := types.GenerateImageFromString(req.GetImage())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "could not parse image %q", req.GetImage())
	}

	var registryCreator types.RegistryClientCreator
	if req.GetRegistry().GetInsecure() {
		registryCreator = types.InsecureDockerRegistryCreator
	} else {
		registryCreator = types.DockerRegistryCreator
	}
	reg, err := registryCreator(req.GetRegistry().GetUrl(), req.GetRegistry().GetUsername(), req.GetRegistry().GetPassword())
	if err != nil {
		return nil, err
	}
	sha, layer, err := s.process(image, reg)
	if err != nil {
		return nil, err
	}
	image.SHA = sha
	if err := s.db.AddImage(layer, image.SHA, image.TaggedName()); err != nil {
		return nil, err
	}

	return &v1.ScanImageResponse{
		Status: v1.ScanStatus_SUCCEEDED,
		Image: &v1.ScanImageResponse_Image{
			Digest: sha,
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

	layer, err := apiV1.LayerFromDatabaseModel(s.db, dbLayer, true, true)
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

func (s *serviceImpl) GetScan(ctx context.Context, req *v1.GetScanRequest) (*v1.GetScanResponse, error) {
	if stringutils.AllEmpty(req.GetImage(), req.GetDigest()) {
		return nil, status.Error(codes.InvalidArgument, "either image or digest must be specified")
	}

	var layerFetcher func(s string) (string, bool, error)
	var argument string
	if digest := req.GetDigest(); digest != "" {
		logrus.Debugf("Getting layer SHA by digest %s", digest)
		argument = digest
		layerFetcher = s.db.GetLayerBySHA
	} else {
		logrus.Debugf("Getting layer SHA by image %s", req.GetImage())
		argument = req.GetImage()
		layerFetcher = s.db.GetLayerByName
	}
	layer, exists, err := layerFetcher(argument)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, status.Errorf(codes.NotFound, "image with reference %q not found", argument)
	}
	return s.getLayer(layer)
}

// RegisterServiceServer registers this service with the given gRPC Server.
func (s *serviceImpl) RegisterServiceServer(grpcServer *grpc.Server) {
	v1.RegisterScanServiceServer(grpcServer, s)
}

// RegisterServiceHandler registers this service with the given gRPC Gateway endpoint.
func (s *serviceImpl) RegisterServiceHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return v1.RegisterScanServiceHandler(ctx, mux, conn)
}
