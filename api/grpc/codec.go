package grpc

import (
	"github.com/planetscale/vtprotobuf/codec/grpc"
	"google.golang.org/grpc/encoding"

	// We want to use the vtprotobuf gRPC codec instead of the official one.
	// Therefore, ensure that the below init() function is executed _after_ the
	// registration of the official protobuf codec, such that we can overwrite it.
	_ "google.golang.org/grpc/encoding/proto"
)

func init() {
	encoding.RegisterCodec(grpc.Codec{})
}
