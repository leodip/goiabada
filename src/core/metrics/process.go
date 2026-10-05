package metrics

import (
	"runtime"

	"github.com/leodip/goiabada/core/buildinfo"
)

// RegisterBuildInfo registers goiabada_build_info, a gauge always 1 whose labels are this binary's
// own build stamp, the version and commit the release build writes with -ldflags -X. Each label's
// set is the one value this binary carries, so the family is one series.
//
// A stamp written empty reads unknown, the value build-docker-images.sh writes for a commit it
// cannot read. The server Dockerfiles pass every -X whether or not its build argument was given,
// so a docker build without them stamps the empty string, which the registry refuses with a
// panic; both servers register this family at every start, metrics on or off, so that build
// would never start.
func RegisterBuildInfo(reg *Registry) {
	version, commit := stampOrUnknown(buildinfo.Version), stampOrUnknown(buildinfo.GitCommit)
	info := reg.Gauge("goiabada_build_info", "The version and commit this binary was built from, always 1.",
		Described("version", "this binary's version", version),
		Described("commit", "this binary's commit", commit))
	info.Set(1, version, commit)
}

func stampOrUnknown(stamp string) string {
	if stamp == "" {
		return "unknown"
	}
	return stamp
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
