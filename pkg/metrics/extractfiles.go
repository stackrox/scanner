package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	fileExtractionCountMetric = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "file_extraction_count",
		Help:    "Number of files in a node filesystem scan",
		Buckets: []float64{50, 100, 500, 1000},
	})

	fileExtractionMatchCountMetric = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "file_extraction_match_count",
		Help:    "Number of matched files in an node filesystem scan",
		Buckets: []float64{50, 100, 500, 1000},
	})

	fileExtractionErrorCountMetric = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "file_extraction_error_count",
		Help:    "Number of files in an node filesystem scan that failed to read",
		Buckets: []float64{50, 100, 500, 1000},
	})
)

func init() {
	prometheus.MustRegister(
		fileExtractionCountMetric,
		fileExtractionMatchCountMetric,
		fileExtractionErrorCountMetric,
	)
}

// FileExtractionMetrics tracks and emit node extraction metrics.
type FileExtractionMetrics struct {
	fileCount, matchCount, errorCount float64
}

// FileCount increments the file count.
func (m *FileExtractionMetrics) FileCount() {
	if m != nil {
		m.fileCount++
	}
}

// MatchCount increments the file match count.
func (m *FileExtractionMetrics) MatchCount() {
	if m != nil {
		m.matchCount++
	}
}

// ErrorCount increments the file error count that were ignored and treated as
// non-existent files.
func (m *FileExtractionMetrics) ErrorCount() {
	if m != nil {
		m.errorCount++
	}
}

// Emit emits the metrics and reset counters
func (m *FileExtractionMetrics) Emit() {
	if m != nil {
		fileExtractionCountMetric.Observe(m.matchCount)
		fileExtractionMatchCountMetric.Observe(m.fileCount)
		fileExtractionErrorCountMetric.Observe(m.errorCount)
	}
	*m = FileExtractionMetrics{}
}
