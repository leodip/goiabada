package metrics

import (
	"runtime"

	"github.com/leodip/goiabada/core/buildinfo"
)

// RegisterBuildInfo registers goiabada_build_info, a gauge always 1 whose labels are this binary's
// own build stamp, the version and commit the release build writes with -ldflags -X. Each label's
// set is the one value this binary carries, so the family is one series.
func RegisterBuildInfo(reg *Registry) {
	info := reg.Gauge("goiabada_build_info", "The version and commit this binary was built from, always 1.",
		Described("version", "this binary's version", buildinfo.Version),
		Described("commit", "this binary's commit", buildinfo.GitCommit))
	info.Set(1, buildinfo.Version, buildinfo.GitCommit)
}

// RegisterRuntime registers go_goroutines and go_memstats_heap_inuse_bytes, read at every scrape,
// under the names and help Go dashboards already read them by.
func RegisterRuntime(reg *Registry) {
	reg.GaugeFunc("go_goroutines", "Number of goroutines that currently exist.", func() float64 {
		return float64(runtime.NumGoroutine())
	})
	reg.GaugeFunc("go_memstats_heap_inuse_bytes", "Number of heap bytes that are in use.", func() float64 {
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		return float64(stats.HeapInuse)
	})
}
