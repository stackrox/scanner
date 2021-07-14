package metrics

import (
	"io/ioutil"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stackrox/rox/pkg/stringutils"
)

const statFile = "/sys/fs/cgroup/cpu/cpu.stat"

func gatherThrottleMetricsForever() {
	processCPUPeriods := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "process_cpu_nr_periods",
		Help: "Number of CPU Periods (nr_periods)",
	})

	processCPUThrottledCount := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "process_cpu_nr_throttled",
		Help: "Number of times the process was throttled",
	})

	processCPUThrottledTime := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "process_cpu_throttled_time",
		Help: "Time in nanoseconds that the process has been throttled",
	})
	prometheus.MustRegister(
		processCPUPeriods,
		processCPUThrottledCount,
		processCPUThrottledTime,
	)

	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		data, err := ioutil.ReadFile(statFile)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			metric, strValue := stringutils.Split2(line, " ")
			if strValue == "" {
				continue
			}
			value, err := strconv.ParseInt(strValue, 10, 64)
			if err != nil {
				continue
			}

			switch metric {
			case "nr_periods":
				processCPUPeriods.Set(float64(value))
			case "nr_throttled":
				processCPUThrottledCount.Set(float64(value))
			case "throttled_time":
				processCPUThrottledTime.Set(float64(value))
			default:
				continue
			}
		}
	}
}
