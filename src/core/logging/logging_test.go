package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/errs"
)

// -----------------------------------------------------------------------------
// Seam 1: the handler Install builds
//
// Everything that needs no process default is driven through newHandler with a
// buffer, so the cases say what bytes reach stderr without touching the global
// slog default. The Install cases below are the exception, and each one restores
// the previous default.
// -----------------------------------------------------------------------------

func handlerFor(t *testing.T, w io.Writer, level, format string) slog.Handler {
	t.Helper()
	handler, err := newHandler(w, level, format)
	require.NoError(t, err)
	return handler
}

// contextWithRequestID builds what chi's RequestID middleware leaves on a
// request context, which is the only thing the wrapper reads.
func contextWithRequestID(requestId string) context.Context {
	return context.WithValue(context.Background(), chimiddleware.RequestIDKey, requestId)
}

// decodeJSON reads the one record written to buf.
func decodeJSON(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	record := map[string]any{}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &record), "record was %q", buf.String())
	return record
}

var levelTable = []struct {
	configured string
	level      slog.Level
}{
	{"debug", slog.LevelDebug},
	{"info", slog.LevelInfo},
	{"warn", slog.LevelWarn},
	{"error", slog.LevelError},
}

func TestNewHandler_LevelAdmitsAndRefuses(t *testing.T) {
	// The exhaustive table: four configured levels against four record levels,
	// under both formats. Debug is the level the twelve Debug call sites in the
	// tree are only reachable at, so the debug row is what makes them more than
	// dead code.
	for _, configured := range levelTable {
		for _, record := range levelTable {
			for _, format := range []string{"text", "json"} {
				t.Run(fmt.Sprintf("%s/%s at %s", format, record.configured, configured.configured), func(t *testing.T) {
					buf := &bytes.Buffer{}
					slog.New(handlerFor(t, buf, configured.configured, format)).
						Log(context.Background(), record.level, "a record")

					if record.level >= configured.level {
						assert.Contains(t, buf.String(), "a record", "the record must be admitted")
						return
					}
					assert.Empty(t, buf.String(), "the record must be refused")
				})
			}
		}
	}
}

func TestNewHandler_TextShape(t *testing.T) {
	buf := &bytes.Buffer{}
	slog.New(handlerFor(t, buf, "info", "text")).Info("a record", "client_identifier", "web")

	line := buf.String()
	assert.Contains(t, line, "time=")
	assert.Contains(t, line, "level=INFO")
	assert.Contains(t, line, `msg="a record"`)
	assert.Contains(t, line, "client_identifier=web")
}

func TestNewHandler_JSONShape(t *testing.T) {
	buf := &bytes.Buffer{}
	slog.New(handlerFor(t, buf, "info", "json")).Info("a record", "client_identifier", "web")

	record := decodeJSON(t, buf)
	assert.NotEmpty(t, record["time"])
	assert.Equal(t, "INFO", record["level"])
	assert.Equal(t, "a record", record["msg"])
	assert.Equal(t, "web", record["client_identifier"])
}

func origin() error { return errs.New("boom") }

func TestNewHandler_ErrorAttributeCarriesItsStack(t *testing.T) {
	// The regression guard for the probe: slog's JSON handler writes err.Error()
	// for an error value, so before ReplaceAttr this record read "wrapped: boom"
	// and carried no frame at all. Text has always printed %+v.
	err := errs.Wrap(origin(), "wrapped")

	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			slog.New(handlerFor(t, buf, "info", format)).Error("a database error", "error", err)

			assert.Contains(t, buf.String(), "wrapped: boom")
			assert.Contains(t, buf.String(), "logging_test.go",
				"the origin frame must survive under %s", format)
		})
	}
}

func TestNewHandler_InjectsTheRequestIdFromTheContext(t *testing.T) {
	t.Run("a context carrying one", func(t *testing.T) {
		buf := &bytes.Buffer{}
		slog.New(handlerFor(t, buf, "info", "json")).
			InfoContext(contextWithRequestID("abc"), "a record")

		assert.Equal(t, "abc", decodeJSON(t, buf)["request_id"])
	})

	t.Run("a context carrying none", func(t *testing.T) {
		buf := &bytes.Buffer{}
		slog.New(handlerFor(t, buf, "info", "json")).
			InfoContext(context.Background(), "a record")

		_, present := decodeJSON(t, buf)["request_id"]
		assert.False(t, present, "nothing must be invented when no id is on the context")
	})
}

func TestNewHandler_BoundsTheRequestIdItInjects(t *testing.T) {
	// chi's RequestID middleware adopts an inbound X-Request-Id verbatim, so this
	// string is client-chosen. Without FieldForLog one header makes one 900 KB
	// log line, on every record of that request rather than just the access line
	// (#159).
	tests := []struct {
		name      string
		requestId string
	}{
		{name: "900000 printable bytes", requestId: strings.Repeat("x", 900000)},
		{name: "900000 non-printable bytes", requestId: strings.Repeat("\x80", 900000)},
		{name: "an embedded carriage return", requestId: "a\x0db"},
	}

	for _, test := range tests {
		for _, format := range []string{"text", "json"} {
			t.Run(test.name+"/"+format, func(t *testing.T) {
				want := FieldForLog(test.requestId)

				buf := &bytes.Buffer{}
				slog.New(handlerFor(t, buf, "info", format)).
					InfoContext(contextWithRequestID(test.requestId), "a record")

				if format == "json" {
					assert.Equal(t, want, decodeJSON(t, buf)["request_id"])
					return
				}
				assert.Contains(t, buf.String(), want)
				assert.Less(t, buf.Len(), 1024, "the whole line must stay bounded")
			})
		}
	}
}

func TestNewHandler_KeepsTheInjectionThroughWithAttrs(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := slog.New(handlerFor(t, buf, "info", "json")).With("component", "token")
	logger.InfoContext(contextWithRequestID("abc"), "a record")

	record := decodeJSON(t, buf)
	assert.Equal(t, "token", record["component"])
	assert.Equal(t, "abc", record["request_id"])
}

func TestNewHandler_KeepsTheRequestIdAtTheRootUnderAGroup(t *testing.T) {
	// slog's contract qualifies every attribute a handler receives after
	// WithGroup by that group. A wrapper that re-wrapped the grouped handler
	// would therefore write operation.request_id, and a collector correlating on
	// request_id would stop finding it.
	t.Run("one group", func(t *testing.T) {
		buf := &bytes.Buffer{}
		logger := slog.New(handlerFor(t, buf, "info", "json")).WithGroup("operation")
		logger.InfoContext(contextWithRequestID("abc"), "a record", "result", "ok")

		record := decodeJSON(t, buf)
		assert.Equal(t, "abc", record["request_id"], "request_id belongs at the record root")
		group, ok := record["operation"].(map[string]any)
		require.True(t, ok, "record was %q", buf.String())
		assert.Equal(t, "ok", group["result"])
		assert.NotContains(t, group, "request_id")
	})

	t.Run("nested groups, with attributes on each", func(t *testing.T) {
		buf := &bytes.Buffer{}
		logger := slog.New(handlerFor(t, buf, "info", "json")).
			With("component", "token").
			WithGroup("operation").
			With("step", "exchange").
			WithGroup("inner")
		logger.InfoContext(contextWithRequestID("abc"), "a record", "result", "ok")

		record := decodeJSON(t, buf)
		assert.Equal(t, "abc", record["request_id"])
		assert.Equal(t, "token", record["component"])

		operation, ok := record["operation"].(map[string]any)
		require.True(t, ok, "record was %q", buf.String())
		assert.Equal(t, "exchange", operation["step"])

		inner, ok := operation["inner"].(map[string]any)
		require.True(t, ok, "record was %q", buf.String())
		assert.Equal(t, "ok", inner["result"])
	})

	t.Run("two groups opened from one handler do not overwrite each other", func(t *testing.T) {
		// The aliasing case: recording the calls in a shared backing array would
		// let the second WithGroup rename the first one's entry.
		buf := &bytes.Buffer{}
		base := handlerFor(t, buf, "info", "json")

		first := slog.New(base.WithGroup("one"))
		second := slog.New(base.WithGroup("two"))

		first.InfoContext(contextWithRequestID("abc"), "a record", "result", "ok")
		firstRecord := decodeJSON(t, buf)

		buf.Reset()
		second.InfoContext(contextWithRequestID("abc"), "a record", "result", "ok")
		secondRecord := decodeJSON(t, buf)

		assert.Contains(t, firstRecord, "one")
		assert.NotContains(t, firstRecord, "two")
		assert.Contains(t, secondRecord, "two")
		assert.NotContains(t, secondRecord, "one")
	})
}

// -----------------------------------------------------------------------------
// Install
// -----------------------------------------------------------------------------

// installSentinel makes a recognisable logger the process default and restores
// the previous one afterwards, so a refusal can be told from an install.
func installSentinel(t *testing.T) *slog.Logger {
	t.Helper()
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })

	sentinel := slog.New(slog.NewTextHandler(io.Discard, nil))
	slog.SetDefault(sentinel)
	return sentinel
}

func TestInstall_RefusesAnUnknownSettingBeforeInstallingAnything(t *testing.T) {
	tests := []struct {
		name     string
		level    string
		format   string
		wantText []string
	}{
		{
			name: "an unknown level", level: "verbose", format: "text",
			wantText: []string{`"verbose"`, "debug, info, warn, error"},
		},
		{
			name: "a level in the wrong case", level: "INFO", format: "text",
			wantText: []string{`"INFO"`, "debug, info, warn, error"},
		},
		{
			name: "an empty level", level: "", format: "text",
			wantText: []string{`""`, "debug, info, warn, error"},
		},
		{
			name: "an unknown format", level: "info", format: "logfmt",
			wantText: []string{`"logfmt"`, "text, json"},
		},
		{
			name: "a format in the wrong case", level: "info", format: "JSON",
			wantText: []string{`"JSON"`, "text, json"},
		},
		{
			name: "an empty format", level: "info", format: "",
			wantText: []string{`""`, "text, json"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sentinel := installSentinel(t)

			err := Install(test.level, test.format)

			require.Error(t, err)
			for _, want := range test.wantText {
				assert.Contains(t, err.Error(), want)
			}
			assert.Same(t, sentinel, slog.Default(),
				"a refused setting must leave the previous default in place")
		})
	}
}

func TestInstall_InstallsTheHandler(t *testing.T) {
	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			sentinel := installSentinel(t)

			require.NoError(t, Install("info", format))

			assert.NotSame(t, sentinel, slog.Default())
		})
	}
}

func TestInstall_RequestIdReachesARecordLoggedFromAHandler(t *testing.T) {
	// The one end-to-end case: a real request, through chi's real RequestID
	// middleware, into a handler that names no id at all. It is what decision 2
	// promises, and it also shows the bound applies to an id the client chose.
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })

	buf := &bytes.Buffer{}
	slog.SetDefault(slog.New(handlerFor(t, buf, "info", "json")))

	oversized := strings.Repeat("x", 900000)
	handler := chimiddleware.RequestID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		slog.InfoContext(r.Context(), "a record")
	}))

	request := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	request.Header.Set(chimiddleware.RequestIDHeader, oversized)
	handler.ServeHTTP(httptest.NewRecorder(), request)

	assert.Equal(t, FieldForLog(oversized), decodeJSON(t, buf)["request_id"])
}
