package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	promErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "clair_pgsql_errors_total",
		Help: "Number of errors that PostgreSQL requests generated.",
	}, []string{"request"})

	promCacheHitsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "clair_pgsql_cache_hits_total",
		Help: "Number of cache hits that the PostgreSQL backend did.",
	}, []string{"object"})

	promCacheQueriesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "clair_pgsql_cache_queries_total",
		Help: "Number of cache queries that the PostgreSQL backend did.",
	}, []string{"object"})

	promQueryDurationMilliseconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "clair_pgsql_query_duration_milliseconds",
		Help:    "Time it takes to execute the database query.",
		Buckets: []float64{1, 10, 100, 500, 1000, 2000, 5000, 10000},
	}, []string{"query", "subquery"})

	promConcurrentLockVAFV = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "clair_pgsql_concurrent_lock_vafv_total",
		Help: "Number of transactions trying to hold the exclusive Vulnerability_Affects_FeatureVersion lock.",
	})
)

// MustRegisterAll registers all prometheus metrics and panics upon error.
func MustRegisterAll() {
	prometheus.MustRegister(
		promErrorsTotal,
		promCacheHitsTotal,
		promCacheQueriesTotal,
		promQueryDurationMilliseconds,
		promConcurrentLockVAFV,
	)
}

// IncErrors increments the error total metric with the given description of the error.
func IncErrors(description string) {
	promErrorsTotal.WithLabelValues(description).Inc()
}

// IncCacheQueries increments the number of cache queries.
func IncCacheQueries(labels ...string) {
	promCacheQueriesTotal.WithLabelValues(labels...).Inc()
}

// IncCacheHits increments the number of cache hits.
func IncCacheHits(labels ...string) {
	promCacheHitsTotal.WithLabelValues(labels...).Inc()
}

// ObserveQueryTime observes the given query and subquery from the given start time.
func ObserveQueryTime(query, subquery string, start time.Time) {
	promQueryDurationMilliseconds.
		WithLabelValues(query, subquery).
		Observe(float64(time.Since(start).Nanoseconds()) / float64(time.Millisecond))
}

// IncLockVAFV increments the number of transactions trying to acquire the VAFV lock.
func IncLockVAFV() {
	promConcurrentLockVAFV.Inc()
}

// DecLockVAFV decrements the number of transactions trying to acquire the VAFV lock.
func DecLockVAFV() {
	promConcurrentLockVAFV.Dec()
}
