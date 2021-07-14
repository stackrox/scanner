package metrics

import (
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

// HTTPServer is a HTTP server for exporting Prometheus metrics.
type HTTPServer struct {
	Address     string
	Gatherer    prometheus.Gatherer
	HandlerOpts promhttp.HandlerOpts
}

// NewDefaultHTTPServer creates and returns a new metrics http server with configured settings.
func NewDefaultHTTPServer(config *api.Config) *HTTPServer {
	addr := defaultAddress
	if port := config.MetricsPort; port != nil {
		if *port == 0 {
			return nil
		}
		addr = fmt.Sprintf(":%d", *port)
	}
	return &HTTPServer{
		Address:  addr,
		Gatherer: prometheus.DefaultGatherer,
	}
}

// RunForever starts the HTTP server in the background.
func (s *HTTPServer) RunForever() {
	if s == nil {
		return
	}
	mux := http.NewServeMux()
	mux.Handle(metricsURLPath, promhttp.HandlerFor(s.Gatherer, s.HandlerOpts))
	httpServer := &http.Server{
		Addr:    s.Address,
		Handler: mux,
	}

	go gatherThrottleMetricsForever()
	go runForever(httpServer)
}

func runForever(server *http.Server) {
	err := server.ListenAndServe()
	// The HTTP server should never terminate.
	log.Panicf("Unexpected termination of metrics HTTP server: %v", err)
}
