package testutil

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Seam 3. CaptureSlog is both the seam every migrated suite asserts through and a unit in its own
// right: a recorder that dropped an attribute, flattened a group differently or stopped injecting
// request_id would not fail here, it would quietly weaken every assertion in three modules that
// reads a log record (#320 decision 11).

// oneRecord requires exactly one captured record and returns it. Exactly one throughout, because a
// helper that captured a record twice would satisfy every "the attribute is there" assertion in
// the tree while telling an operator the event happened twice.
func oneRecord(t *testing.T, capture *SlogCapture) CapturedRecord {
	t.Helper()
	records := capture.Records()
	require.Len(t, records, 1, "want exactly one captured record")
	return records[0]
}

func TestCaptureSlog_CapturesLevelMessageAndAttributes(t *testing.T) {
	capture := CaptureSlog(t)

	slog.Warn("a refusal", "client_identifier", "web", "user_id", int64(7))

	record := oneRecord(t, capture)
	assert.Equal(t, slog.LevelWarn, record.Level)
	assert.Equal(t, "a refusal", record.Message)
	assert.Equal(t, map[string]any{"client_identifier": "web", "user_id": int64(7)}, record.Attrs)
}

// Debug is the level that would be lost silently. slog's built-in default drops it, so a recorder
// that inherited a level rather than declaring its own would make the twelve Debug sites decision
// 10 keeps unobservable, and a test written against one of them would pass with the site deleted.
func TestCaptureSlog_CapturesEveryLevelIncludingDebug(t *testing.T) {
	capture := CaptureSlog(t)

	slog.Debug("a trace")
	slog.Info("a lifecycle line")
	slog.Warn("a refusal")
	slog.Error("a fault")

	var levels []slog.Level
	var messages []string
	for _, record := range capture.Records() {
		levels = append(levels, record.Level)
		messages = append(messages, record.Message)
	}
	assert.Equal(t, []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError}, levels)
	assert.Equal(t, []string{"a trace", "a lifecycle line", "a refusal", "a fault"}, messages)
}

// The injection is why the recorder sits under the servers' own wrapper instead of being installed
// bare. Every level test and level pin the later stages write reads request_id through this path.
func TestCaptureSlog_ARecordLoggedWithChisRequestIdCarriesIt(t *testing.T) {
	capture := CaptureSlog(t)

	ctx := context.WithValue(context.Background(), chimiddleware.RequestIDKey, "req-abc-123")
	slog.InfoContext(ctx, "a record")

	assert.Equal(t, "req-abc-123", oneRecord(t, capture).Attrs["request_id"])
}

// The other half, and the one that fails if the wrapper ever starts inventing an id: a startup
// line has no request to correlate to, and an attribute there would be a fabricated join key.
func TestCaptureSlog_ARecordWithNoRequestIdCarriesNothing(t *testing.T) {
	capture := CaptureSlog(t)

	slog.Info("a startup line")

	assert.NotContains(t, oneRecord(t, capture).Attrs, "request_id")
}

// The end-to-end shape the migrated suites use: a real chi router, the real RequestID middleware,
// and a handler that logs with the request's context. Driving the middleware rather than planting
// the context value is what makes this a check on the pair, since the key is chi's and unexported.
func TestCaptureSlog_ARequestThroughChiCorrelatesTheHandlersRecord(t *testing.T) {
	capture := CaptureSlog(t)

	router := chi.NewRouter()
	router.Use(chimiddleware.RequestID)
	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		slog.InfoContext(r.Context(), "a handler record")
	})

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set(chimiddleware.RequestIDHeader, "req-from-the-edge")
	router.ServeHTTP(httptest.NewRecorder(), request)

	record := oneRecord(t, capture)
	assert.Equal(t, "a handler record", record.Message)
	assert.Equal(t, "req-from-the-edge", record.Attrs["request_id"])
}

func TestCaptureSlog_TextRendersALinePerRecord(t *testing.T) {
	capture := CaptureSlog(t)

	slog.Info("first record", "client_identifier", "web")
	slog.Error("second record")

	lines := strings.Split(strings.TrimSpace(capture.Text()), "\n")
	require.Len(t, lines, 2)
	assert.Contains(t, lines[0], `level=INFO msg="first record" client_identifier=web`)
	assert.Contains(t, lines[1], `level=ERROR msg="second record"`)
}

// A logger built through slog.With is not something production does, and that is exactly why the
// recorder has to model it: the private recorders this replaced were written against one suite
// each, and three of the four dropped WithAttrs on the floor.
func TestCaptureSlog_AttributesFromWithReachTheRecord(t *testing.T) {
	capture := CaptureSlog(t)

	slog.Default().With("component", "token").Info("a record", "key_id", int64(3))

	assert.Equal(t, map[string]any{"component": "token", "key_id": int64(3)},
		oneRecord(t, capture).Attrs)
}

func TestCaptureSlog_AGroupFlattensToDottedKeys(t *testing.T) {
	capture := CaptureSlog(t)

	slog.Default().WithGroup("operation").Info("a record", "name", "issue_code")

	assert.Equal(t, map[string]any{"operation.name": "issue_code"}, oneRecord(t, capture).Attrs)
}

func TestCaptureSlog_AnInlineGroupFlattensTheSameWay(t *testing.T) {
	capture := CaptureSlog(t)

	slog.Info("a record", slog.Group("db", "name", "goiabada", "port", 5432))

	// int64 rather than int: slog widens every integer, so this is what a suite reading Attrs has
	// to compare against.
	assert.Equal(t, map[string]any{"db.name": "goiabada", "db.port": int64(5432)},
		oneRecord(t, capture).Attrs)
}

// The documented resolution of a collision, asserted rather than described: Attrs is a map, so it
// has to choose, and Text() does not have to. A suite reading Attrs gets what a person reading the
// rendered line would take the record to mean.
func TestCaptureSlog_ADuplicateKeyKeepsTheLastInAttrsAndBothInText(t *testing.T) {
	capture := CaptureSlog(t)

	slog.Info("a record", "user_id", int64(1), "user_id", int64(2))

	assert.Equal(t, int64(2), oneRecord(t, capture).Attrs["user_id"])
	assert.Contains(t, capture.Text(), "user_id=1 user_id=2")
}

// resolvedValue renders as its LogValue, which is the only thing a handler ever writes. Storing the
// LogValuer itself would give a suite a value no log line ever contained.
type resolvedValue struct{}

func (resolvedValue) LogValue() slog.Value { return slog.StringValue("resolved") }

func TestCaptureSlog_ALogValuerIsResolved(t *testing.T) {
	capture := CaptureSlog(t)

	slog.Info("a record", "value", resolvedValue{})

	assert.Equal(t, "resolved", oneRecord(t, capture).Attrs["value"])
}

// slog.Handler's contract requires a handler to be safe for concurrent use, and the helper forbids
// t.Parallel() only for the default it installs, not for a test that logs from its own goroutines.
// This is the case the race leg reads.
func TestCaptureSlog_IsSafeForConcurrentUse(t *testing.T) {
	capture := CaptureSlog(t)

	var wg sync.WaitGroup
	for worker := 0; worker < 2; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				slog.Info("a record")
			}
		}()
	}
	wg.Wait()

	assert.Len(t, capture.Records(), 100, "every record from both goroutines is kept")
}

func TestCaptureSlog_RestoresThePreviousDefaultOnCleanup(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })

	sentinel := slog.New(slog.NewTextHandler(io.Discard, nil))
	slog.SetDefault(sentinel)

	t.Run("inner", func(t *testing.T) {
		CaptureSlog(t)
		require.NotSame(t, sentinel, slog.Default(), "the capture has to be installed for the subtest")
	})

	assert.Same(t, sentinel, slog.Default(),
		"a helper that leaked its recorder would silently swallow every later test's output")
}
