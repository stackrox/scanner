package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	golog "log"
	"net"
	"net/http"
	"strings"

	"github.com/NYTimes/gziphandler"
	grpcmiddleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpcprometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/pkg/env"
	"github.com/stackrox/scanner/pkg/mtls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	localEndpoint = "127.0.0.1:8444"
)

func init() {
	grpcprometheus.EnableHandlingTimeHistogram()
}

func maxGrpcConcurrentStreams() uint32 {
	if env.MaxGrpcConcurrentStreams.Int() <= 0 {
		return env.DefaultMaxGrpcConcurrentStreams
	}

	return uint32(env.MaxGrpcConcurrentStreams.Int())
}

// NewAPI creates a new gRPC API instantiation
func NewAPI(config Config) API {
	return &apiImpl{
		config: config,
	}
}

func (a *apiImpl) listenOnLocalEndpoint(server *grpc.Server) error {
	lis, err := net.Listen("tcp", localEndpoint)
	if err != nil {
		return err
	}

	log.Infof("Launching backend GRPC listener on %v", localEndpoint)
	// Launch the GRPC listener
	go func() {
		if err := server.Serve(lis); err != nil {
			log.Fatal(err)
		}
		log.Fatal("The local API server should never terminate")
	}()
	return nil
}

func (a *apiImpl) connectToLocalEndpoint() (*grpc.ClientConn, error) {
	return grpc.Dial(localEndpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
}

func (a *apiImpl) Start() {
	grpcServer := grpc.NewServer(
		grpcmiddleware.WithUnaryServerChain(a.unaryInterceptors()...),
		grpc.MaxConcurrentStreams(maxGrpcConcurrentStreams()),
	)

	for _, serv := range a.apiServices {
		serv.RegisterServiceServer(grpcServer)
	}

	if err := a.listenOnLocalEndpoint(grpcServer); err != nil {
		log.Fatal(err)
	}

	conn, err := a.connectToLocalEndpoint()
	if err != nil {
		panic(err)
	}

	gwHandler := a.muxer(conn)

	addr := fmt.Sprintf(":%d", a.config.Port)
	log.Infof("Listening on public endpoint: %v", addr)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	conf, err := mtls.TLSServerConfig()
	if err != nil {
		log.Fatal(err)
	}

	lis = tls.NewListener(lis, conf)
	handler := httpGrpcRouter(grpcServer, gwHandler)
	go func() {
		server := http.Server{
			Handler:  handler,
			ErrorLog: golog.New(httpErrorLogger{}, "", golog.LstdFlags),
		}
		log.Fatal(server.Serve(lis))
	}()
}

// APIService is the service interface
type APIService interface {
	RegisterServiceServer(server *grpc.Server)
	RegisterServiceHandler(context.Context, *runtime.ServeMux, *grpc.ClientConn) error
}

// API listens for new connections on port 443, and redirects them to the gRPC-Gateway
type API interface {
	// Start runs the API in a goroutine, and returns a signal that can be checked for when the API server is started.
	Start()
	// Register adds a new APIService to the list of API services
	Register(services ...APIService)
}

type apiImpl struct {
	apiServices []APIService
	config      Config
}

// A Config configures the server.
type Config struct {
	Port         int
	CustomRoutes map[string]http.Handler
}

func (a *apiImpl) Register(services ...APIService) {
	a.apiServices = append(a.apiServices, services...)
}

func (a *apiImpl) unaryInterceptors() []grpc.UnaryServerInterceptor {
	// Interceptors are executed in order.
	return []grpc.UnaryServerInterceptor{
		// Ensure the user is authorized before doing anything else.
		verifyPeerCertsUnaryServerInterceptor(),
		slimModeUnaryServerInterceptor(),
		grpcprometheus.UnaryServerInterceptor,
	}
}

func (a *apiImpl) muxer(localConn *grpc.ClientConn) http.Handler {
	mux := http.NewServeMux()
	for route, handler := range a.config.CustomRoutes {
		mux.Handle(route, handler)
	}

	gwMux := runtime.NewServeMux(runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{EmitDefaults: true}))
	for _, service := range a.apiServices {
		if err := service.RegisterServiceHandler(context.Background(), gwMux, localConn); err != nil {
			log.Panicf("failed to register API service: %v", err)
		}
	}
	mux.Handle("/v1/", gziphandler.GzipHandler(gwMux))
	return mux
}

func httpGrpcRouter(grpcServer *grpc.Server, httpHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
		} else {
			httpHandler.ServeHTTP(w, r)
		}
	})
}
