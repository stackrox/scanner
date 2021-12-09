package imagescan

import v1 "github.com/stackrox/scanner/generated/shared/api/v1"

// imageRequest is an interface wrapper for a v1 image-related request.
type imageRequest interface {
	GetImageSpec() *v1.ImageSpec
	GetUncertifiedRHEL() bool
}

// imageReq is an implementation of imageRequest.
type imageReq struct {
	imageSpec       *v1.ImageSpec
	uncertifiedRHEL bool
}

func (i *imageReq) GetImageSpec() *v1.ImageSpec {
	return i.imageSpec
}

func (i *imageReq) GetUncertifiedRHEL() bool {
	return i.uncertifiedRHEL
}
