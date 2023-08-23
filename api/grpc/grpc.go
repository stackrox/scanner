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
	grpcprometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/pkg/httputil"
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

// NewAPI creates a new gRPC API instantiation
func NewAPI(opts ...ConfigOpts) API {
	var config Config
	for _, opt := range opts {
		opt(&config)
	}

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
	grpcServer := grpc.NewServer(grpc.ChainUnaryInterceptor(a.config.UnaryInterceptors...))
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

	grpcHandler := httputil.WithLogging(grpcServer, httputil.GRPC)
	gwHandler := httputil.WithLogging(a.muxer(conn), httputil.HTTP)

	var publicListener net.Listener
	if a.config.PublicEndpoint {
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

		publicListener = tls.NewListener(lis, conf)
		handler := httpGrpcRouter(grpcHandler, gwHandler)
		go func() {
			server := http.Server{
				Handler:  handler,
				ErrorLog: golog.New(httpErrorLogger{}, "", golog.LstdFlags),
			}
			log.Fatal(server.Serve(publicListener))
		}()
	}
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
	Port              int
	CustomRoutes      map[string]http.Handler
	UnaryInterceptors []grpc.UnaryServerInterceptor
	PublicEndpoint    bool
}

// ConfigOpts defines configurations to start a gRPC server.
type ConfigOpts func(cfg *Config)

// WithTLSEndpoint starts the gRPC server with TLS enabled on port.
func WithTLSEndpoint(port int) ConfigOpts {
	return func(cfg *Config) {
		cfg.Port = port
		cfg.PublicEndpoint = true
	}
}

// WithDefaultInterceptors should be used when starting Scanner API. This interceptors list contains interceptors
// that check method availability on slim mode and TLS client checks.
func WithDefaultInterceptors() ConfigOpts {
	return func(cfg *Config) {
		// Interceptors are executed in order.
		cfg.UnaryInterceptors = []grpc.UnaryServerInterceptor{
			// Ensure the user is authorized before doing anything else.
			verifyPeerCertsUnaryServerInterceptor(),
			slimModeUnaryServerInterceptor(),
			grpcprometheus.UnaryServerInterceptor,
		}
	}
}

// WithCustomUnaryInterceptors should be used to set custom GRPC interceptors.
func WithCustomUnaryInterceptors(interceptors ...grpc.UnaryServerInterceptor) ConfigOpts {
	return func(cfg *Config) {
		cfg.UnaryInterceptors = interceptors
	}
}

// WithCustomRoutes sets custom HTTP routes.
func WithCustomRoutes(routes map[string]http.Handler) ConfigOpts {
	return func(cfg *Config) {
		cfg.CustomRoutes = routes
	}
}

func (a *apiImpl) Register(services ...APIService) {
	a.apiServices = append(a.apiServices, services...)
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

func httpGrpcRouter(grpcHandler, httpHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
			grpcHandler.ServeHTTP(w, r)
		} else {
			httpHandler.ServeHTTP(w, r)
		}
	})
}
