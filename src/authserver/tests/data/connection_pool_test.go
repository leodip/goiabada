package datatests

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/datafactory"
	"github.com/leodip/goiabada/authserver/internal/data/mssqldb"
	"github.com/leodip/goiabada/authserver/internal/data/mysqldb"
	"github.com/leodip/goiabada/authserver/internal/data/postgresdb"
	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
	"github.com/leodip/goiabada/authserver/internal/poolmetrics"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// handleOf reaches the *sql.DB behind an opened engine, whose statistics are the one place
// database/sql reads a configured pool back.
func handleOf(t *testing.T, opened datafactory.Migratable) *sql.DB {
	t.Helper()
	switch d := opened.(type) {
	case *sqlitedb.Database:
		return d.DB
	case *mysqldb.Database:
		return d.DB
	case *postgresdb.Database:
		return d.DB
	case *mssqldb.Database:
		return d.DB
	}
	t.Fatalf("no raw handle for database type %T", opened)
	return nil
}

// TestConnectionPool_TheDataTiersOwnHandleRunsOnTheDefaultCap: the package's database was opened
// through datafactory with nothing configured, so on the three server engines its pool is capped
// at the default of 20 rather than unlimited, and SQLite's stays at one (#394 decision 6).
func TestConnectionPool_TheDataTiersOwnHandleRunsOnTheDefaultCap(t *testing.T) {
	want := 20
	if dbType() == data.SQLite {
		want = 1
	}
	assert.Equal(t, want, rawSQLHandle(t).Stats().MaxOpenConnections)
}

// TestConnectionPool_TheConfiguredCapIsTheHandlesMaximum opens the configured engine through
// datafactory.OpenDatabase with a pool of its own, and shows the cap taking: the handle reads it
// back, the start's pool record carries all four values, and with the cap's worth of transactions
// held open a further one waits rather than opening another connection. That last is the issue's
// manual check, GOIABADA_DB_MAX_OPEN_CONNS=2 and no third connection, done by the pool's own
// accounting rather than by the server's. On SQLite the configured values never arrive: one
// connection, one idle, no lifetime, whatever was set (#394).
func TestConnectionPool_TheConfiguredCapIsTheHandlesMaximum(t *testing.T) {
	cfg := appConfig.Database
	cfg.MaxOpenConns = 2
	cfg.MaxIdleConns = nil
	cfg.ConnMaxLifetime = 7 * time.Minute
	cfg.ConnMaxIdleTime = 2 * time.Minute

	wantCap := 2
	wantRecord := map[string]any{
		"max_open_conns":     int64(2),
		"max_idle_conns":     int64(2),
		"conn_max_lifetime":  7 * time.Minute,
		"conn_max_idle_time": 2 * time.Minute,
	}
	if dbType() == data.SQLite {
		wantCap = 1
		wantRecord = map[string]any{
			"max_open_conns":     int64(1),
			"max_idle_conns":     int64(1),
			"conn_max_lifetime":  time.Duration(0),
			"conn_max_idle_time": time.Duration(0),
		}
	}

	capture := logtest.CaptureSlog(t)
	opened, err := datafactory.OpenDatabase(context.Background(), &cfg, false)
	require.NoError(t, err)
	handle := handleOf(t, opened)
	t.Cleanup(func() { _ = handle.Close() })

	assert.Equal(t, wantCap, handle.Stats().MaxOpenConnections, "the handle's cap is the configured one")

	var records []logtest.CapturedRecord
	for _, r := range capture.Records() {
		if r.Message == "database connection pool" {
			records = append(records, r)
		}
	}
	require.Len(t, records, 1, "the open says once what pool it opened: %s", capture.Text())
	assert.Equal(t, wantRecord, records[0].Attrs)

	// The cap's worth of transactions, each holding its connection until it ends.
	ctx := context.Background()
	for i := 0; i < wantCap; i++ {
		tx, beginErr := handle.BeginTx(ctx, nil)
		require.NoErrorf(t, beginErr, "transaction %d of the cap's %d", i+1, wantCap)
		t.Cleanup(func() { _ = tx.Rollback() })
	}

	waitPastTheCap(t, handle)

	stats := handle.Stats()
	assert.Equal(t, wantCap, stats.OpenConnections, "no connection was opened past the cap")
	assert.Positive(t, stats.WaitCount, "the pool counted the wait")
}

// waitPastTheCap begins one transaction more than the pool's cap allows, requires it to queue for a
// connection rather than open one, and ends it by cancelling its context. The cancel comes only
// after the handle counts the request as waiting, so the wait is counted however the goroutine is
// scheduled, where a timeout started before BeginTx could run out before it queued. The 20 ms pause
// gives the wait a realistic duration to report.
func waitPastTheCap(t *testing.T, handle *sql.DB) {
	t.Helper()
	waitsBefore := handle.Stats().WaitCount
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ended := make(chan error, 1)
	go func() {
		tx, err := handle.BeginTx(ctx, nil)
		if err == nil {
			// The cap let it through, which the test reports; the connection goes back at once.
			_ = tx.Rollback()
		}
		ended <- err
	}()
	require.Eventually(t, func() bool { return handle.Stats().WaitCount == waitsBefore+1 }, 10*time.Second,
		time.Millisecond, "a transaction past the cap must wait for a connection, not open one")
	time.Sleep(20 * time.Millisecond)
	cancel()
	err := <-ended
	require.ErrorIsf(t, err, context.Canceled, "it waited until its context ended: %v", err)
}

// poolSamples scrapes reg as Prometheus would and answers the goiabada_db_* samples, each line's
// series mapped to its value as written.
func poolSamples(t *testing.T, reg *metrics.Registry) map[string]string {
	t.Helper()

	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	res := rec.Result()
	require.Equal(t, http.StatusOK, res.StatusCode)
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	samples := map[string]string{}
	for _, line := range strings.Split(string(body), "\n") {
		if !strings.HasPrefix(line, "goiabada_db_") {
			continue
		}
		series, value, found := strings.Cut(line, " ")
		require.True(t, found, line)
		samples[series] = value
	}
	return samples
}

// TestConnectionPool_TheScrapeReportsThePoolAsItIs registers the pool metrics over a real handle
// opened through datafactory.OpenDatabase, as NewServer registers them over the server's, and
// drives the pool through the states an operator watches: the cap's worth of transactions held, a
// further one waiting until its context ends, then every connection given back to an idle cap
// below the open cap, which closes the one it cannot keep. Each scrape reports the pool as it is
// at that moment, read from the handle and not from anything recorded beside it (#400 decision 5).
// On SQLite the pool is one connection, one idle, whatever is configured (#394), so the idle cap
// closes nothing.
func TestConnectionPool_TheScrapeReportsThePoolAsItIs(t *testing.T) {
	cfg := appConfig.Database
	cfg.MaxOpenConns = 2
	idleCap := 1
	cfg.MaxIdleConns = &idleCap
	cfg.ConnMaxLifetime = 7 * time.Minute
	cfg.ConnMaxIdleTime = 2 * time.Minute

	wantCap, wantIdleClosed := 2, 1
	if dbType() == data.SQLite {
		wantCap, wantIdleClosed = 1, 0
	}

	opened, err := datafactory.OpenDatabase(context.Background(), &cfg, false)
	require.NoError(t, err)
	handle := handleOf(t, opened)
	t.Cleanup(func() { _ = handle.Close() })

	reg := metrics.NewRegistry()
	poolmetrics.Register(reg, opened)

	ctx := context.Background()
	held := make([]*sql.Tx, 0, wantCap)
	for i := 0; i < wantCap; i++ {
		tx, beginErr := handle.BeginTx(ctx, nil)
		require.NoErrorf(t, beginErr, "transaction %d of the cap's %d", i+1, wantCap)
		// Closing the handle leaves a transaction still open holding its connection, so a failure
		// before the rollbacks below must not skip them.
		t.Cleanup(func() { _ = tx.Rollback() })
		held = append(held, tx)
	}

	// No request has waited yet, so the wait counters read zero: a collector that kept its first
	// value would fail the scrape after the wait below.
	beforeWait := poolSamples(t, reg)
	assert.Equal(t, "0", beforeWait["goiabada_db_wait_count_total"], "nothing has waited yet")
	assert.Equal(t, "0", beforeWait["goiabada_db_wait_duration_seconds_total"], "nothing has waited yet")

	waitPastTheCap(t, handle)

	atCap := poolSamples(t, reg)
	assert.Equal(t, map[string]string{
		"goiabada_db_max_open_connections":                             strconv.Itoa(wantCap),
		`goiabada_db_connections{state="idle"}`:                        "0",
		`goiabada_db_connections{state="in_use"}`:                      strconv.Itoa(wantCap),
		"goiabada_db_wait_count_total":                                 "1",
		"goiabada_db_wait_duration_seconds_total":                      atCap["goiabada_db_wait_duration_seconds_total"],
		`goiabada_db_connections_closed_total{reason="max_idle"}`:      "0",
		`goiabada_db_connections_closed_total{reason="max_idle_time"}`: "0",
		`goiabada_db_connections_closed_total{reason="max_lifetime"}`:  "0",
	}, atCap, "the pool at its cap, one request having waited")
	// The wait is judged against the handle's own measurement: how long it lasted is the scheduler's
	// to decide, and the metric's job is to report what the handle measured.
	waitDuration := handle.Stats().WaitDuration
	require.Positive(t, waitDuration, "the handle measured a wait")
	assertSeconds(t, atCap["goiabada_db_wait_duration_seconds_total"], waitDuration,
		"the wait is reported in seconds, as the handle measured it")

	for _, tx := range held {
		require.NoError(t, tx.Rollback())
	}

	released := poolSamples(t, reg)
	assert.Equal(t, "0", released[`goiabada_db_connections{state="in_use"}`], "every connection was given back")
	assert.Equal(t, "1", released[`goiabada_db_connections{state="idle"}`], "the idle cap keeps one")
	assert.Equal(t, strconv.Itoa(wantIdleClosed), released[`goiabada_db_connections_closed_total{reason="max_idle"}`],
		"a connection given back to a full idle cap is closed, and counted under max_idle")
	assert.Equal(t, "1", released["goiabada_db_wait_count_total"], "a counter keeps what it counted")
}

// assertSeconds reads an exposition value as seconds and holds it to d. The exposition writes the
// shortest form that reads back as the same float, so the two are equal; the tolerance is there
// because testifylint refuses an exact float comparison.
func assertSeconds(t *testing.T, value string, d time.Duration, msg string) {
	t.Helper()
	seconds, err := strconv.ParseFloat(value, 64)
	require.NoError(t, err, "%q is not a number", value)
	assert.InEpsilon(t, d.Seconds(), seconds, 1e-9, msg)
}
