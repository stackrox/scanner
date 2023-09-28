package tracing

import (
	"os"

	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/rox/pkg/version"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

func ScannerResource() *resource.Resource {
	r, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("scanner"),
			semconv.ServiceVersion(version.GetMainVersion()),
			semconv.K8SPodName(os.Getenv("HOSTNAME")),
		),
	)
	utils.Should(err)
	return r
}
