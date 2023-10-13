package metrics

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/api"
)

const (
	defaultAddress = ":9090"
	metricsURLPath = "/metrics"
)

// HTTPServer is an HTTP server for exporting Prometheus metrics.
type HTTPServer struct {
	server *http.Server
}

// NewHTTPServer creates and returns a new metrics HTTP server with the configured settings.
func NewHTTPServer(config *api.Config) *HTTPServer {
	addr := defaultAddress
	if port := config.MetricsPort; port != nil {
		if *port == 0 {
			return nil
		}
		addr = fmt.Sprintf(":%d", *port)
	}

	mux := http.NewServeMux()
	mux.Handle(metricsURLPath, promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{}))

	return &HTTPServer{
		server: &http.Server{
			Addr:    addr,
			Handler: mux,
			// Setting TLSNextProto to a non-nil empty map disables automatic HTTP/2 support.
			TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		},
	}
}

// RunForever starts the HTTP server in the background.
func (s *HTTPServer) RunForever() {
	if s == nil {
		return
	}

	go gatherThrottleMetricsForever()

	err := s.server.ListenAndServe()
	// The metrics HTTP server should never terminate.
	log.Panicf("Unexpected termination of metrics HTTP server: %v", err)
}
