package grpc

import (
	"context"
	"github.com/sirupsen/logrus"

	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/pkg/env"
	"github.com/stackrox/scanner/pkg/mtls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

var (
	// Method name(s) taken from the respective generated pb.go file(s).
	verifyPeerCertsMethodsAllowList = set.NewFrozenStringSet(
		"/scannerV1.PingService/Ping",
	)
)

func verifyPeerCertsUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	skipPeerValidation := env.SkipPeerValidation.Enabled()

	verifyPeerCertificate := mtls.VerifyCentralPeerCertificate
	if env.SlimMode.Enabled() {
		verifyPeerCertificate = mtls.VerifySensorPeerCertificate
	}

	logrus.WithFields(map[string]interface{}{
		"Skip Peer Validation": skipPeerValidation,
	}).Error("SCANNER IS HERE YAYAYAY")

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		logrus.WithFields(map[string]interface{}{
			"Endpoint": info.FullMethod,
		}).Error("SCANNER CHECKING PEER CERT YAYAYAY")

		if !skipPeerValidation && !verifyPeerCertsMethodsAllowList.Contains(info.FullMethod) {
			peerInfo, exists := peer.FromContext(ctx)
			if !exists {
				return nil, status.Error(codes.InvalidArgument, "unable to parse peer information from request context")
			}
			tlsInfo, ok := peerInfo.AuthInfo.(credentials.TLSInfo)
			if !ok {
				return nil, status.Error(codes.InvalidArgument, "peer auth info is not TLS info")
			}

			if err := verifyPeerCertificate(&tlsInfo.State); err != nil {
				return nil, status.Error(codes.InvalidArgument, err.Error())
			}
		}

		logrus.WithFields(map[string]interface{}{
			"Endpoint": info.FullMethod,
		}).Error("SCANNER ALLOWED PEER CERT YAYAYAY")

		return handler(ctx, req)
	}
}
