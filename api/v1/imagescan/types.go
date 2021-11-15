package imagescan

import v1 "github.com/stackrox/scanner/generated/shared/api/v1"

// imageRequest is an interface wrapper for a v1 image-related request.
type imageRequest interface {
	GetImageSpec() *v1.ImageSpec
	GetUncertifiedRHEL() bool
}

// getLayerOpts represents options for layer retrieval.
type getLayerOpts struct {
	uncertifiedRHEL bool
	withVulns       bool
	withFeatures    bool
}

// imageScanOpts represents options for image scan retrieval.
type imageScanOpts struct {
	withVulns    bool
	withFeatures bool
}
