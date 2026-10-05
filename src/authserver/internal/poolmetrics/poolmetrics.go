// Package poolmetrics reports the database connection pool on the metrics listener: its cap, its
// connections by state, the requests that waited for a connection and for how long, and the
// connections it closed by reason (#400 decision 5). #394 capped the pool and documented that a
// capped pool trades one failure for another, a request waiting for a connection; that wait exists
// only in database/sql's own statistics, so this is where an operator measures it.
//
// Every value is read from the pool at the scrape, never recorded beside it, so what a scrape
// reports is what the pool held then.
package poolmetrics

import (
	"database/sql"

	"github.com/leodip/goiabada/core/metrics"
)

// poolStatsReader is the one read of the pool from above the data layer.
type poolStatsReader interface {
	PoolStats() sql.DBStats
}

// Register registers the five goiabada_db_* families on reg, each read from pool at every scrape.
func Register(reg *metrics.Registry, pool poolStatsReader) {
	reg.GaugeFunc("goiabada_db_max_open_connections",
		"The most connections the database pool may hold open at once.",
		func() float64 { return float64(pool.PoolStats().MaxOpenConnections) })

	reg.GaugeVecFunc("goiabada_db_connections",
		"Connections the database pool holds, by whether a request is using them or they are idle.",
		func() []metrics.Sample {
			stats := pool.PoolStats()
			return []metrics.Sample{
				{Value: float64(stats.InUse), LabelValues: []string{"in_use"}},
				{Value: float64(stats.Idle), LabelValues: []string{"idle"}},
			}
		},
		metrics.Enum("state", "in_use", "idle"))

	reg.CounterFunc("goiabada_db_wait_count_total",
		"Requests that waited for a database connection because the pool was at its cap.",
		func() float64 { return float64(pool.PoolStats().WaitCount) })

	reg.CounterFunc("goiabada_db_wait_duration_seconds_total",
		"Time spent waiting for a database connection, in seconds, summed over every wait.",
		func() float64 { return pool.PoolStats().WaitDuration.Seconds() })

	reg.CounterVecFunc("goiabada_db_connections_closed_total",
		"Connections the database pool closed, by the limit that closed them.",
		func() []metrics.Sample {
			stats := pool.PoolStats()
			return []metrics.Sample{
				{Value: float64(stats.MaxIdleClosed), LabelValues: []string{"max_idle"}},
				{Value: float64(stats.MaxIdleTimeClosed), LabelValues: []string{"max_idle_time"}},
				{Value: float64(stats.MaxLifetimeClosed), LabelValues: []string{"max_lifetime"}},
			}
		},
		metrics.Enum("reason", "max_idle", "max_idle_time", "max_lifetime"))
}
