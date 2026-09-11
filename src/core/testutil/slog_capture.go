package testutil

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/logging"
)

// CaptureSlog redirects slog's default logger into a recorder for one test and restores the
// previous default in t.Cleanup.
//
// The recorder sits under logging.WrapRequestID, which is the handler both servers install, so a
// test asserting on request_id exercises the injection the servers run rather than a second copy
// of it: a record logged with a context carrying chi's request id carries the attribute here for
// the same reason it does in production, and a wrapper that stopped injecting would fail a test
// instead of quietly losing the correlation on every record the product writes (#320 decision 11).
//
// It replaced 14 private installs across three modules, of two shapes that could not assert the
// same things: a text buffer, which cannot see a record's level or tell two records apart, and
// four hand-written recording handlers, each modelling only what its own suite needed.
//
// slog.SetDefault is process-wide, so this is not safe in a test that calls t.Parallel(), nor in a
// package where another test runs in parallel with this one. No test that uses it does.
func CaptureSlog(t *testing.T) *SlogCapture {
	t.Helper()

	capture := &SlogCapture{}
	previous := slog.Default()
	slog.SetDefault(slog.New(logging.WrapRequestID(&recordingHandler{capture: capture})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return capture
}

// CapturedRecord is one record, flattened for assertion.
//
// Attrs holds every attribute the record carried, including those a logger built through
// slog.With contributed, with each value put through Value.Resolve() so a slog.LogValuer is
// stored as what it renders rather than as itself. A group qualifies its members' keys:
// slog.Group("db", "name", "x") is Attrs["db.name"]. A key written twice keeps the last value,
// which is what a reader of the rendered line would take it to mean; Text() still shows both.
type CapturedRecord struct {
	Level   slog.Level
	Message string
	Attrs   map[string]any
}

// SlogCapture holds the records written while a test holds the default logger.
type SlogCapture struct {
	mu      sync.Mutex
	entries []capturedEntry
}

// capturedEntry keeps the flattened attributes in the order they were written, which Attrs cannot
// preserve and Text() needs to render a line that matches what the installed handler would print.
type capturedEntry struct {
	time    time.Time
	level   slog.Level
	message string
	attrs   []slog.Attr
}

// Records returns every record captured so far, in order.
func (c *SlogCapture) Records() []CapturedRecord {
	c.mu.Lock()
	defer c.mu.Unlock()

	records := make([]CapturedRecord, 0, len(c.entries))
	for _, entry := range c.entries {
		attrs := make(map[string]any, len(entry.attrs))
		for _, attr := range entry.attrs {
			attrs[attr.Key] = attr.Value.Any()
		}
		records = append(records, CapturedRecord{
			Level:   entry.level,
			Message: entry.message,
			Attrs:   attrs,
		})
	}
	return records
}

// Text renders the captured records through slog's text handler, one line each, for the suites
// that assert on a line rather than on a record.
//
// Keys are already flattened, so a grouped attribute prints as group.key=v where the installed
// handler would print the same key under a group prefix. Nothing in production opens a group (the
// slog lint refuses slog.With and slog.Default outside core/logging), so for every record the
// product writes this is the line the product writes.
func (c *SlogCapture) Text() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	buf := &bytes.Buffer{}
	handler := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	for _, entry := range c.entries {
		record := slog.NewRecord(entry.time, entry.level, entry.message, 0)
		record.AddAttrs(entry.attrs...)
		// The handler writes to a buffer, which cannot fail.
		_ = handler.Handle(context.Background(), record)
	}
	return buf.String()
}

func (c *SlogCapture) append(entry capturedEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append(c.entries, entry)
}

// recordingHandler is the slog.Handler side of SlogCapture.
//
// It implements the full handler contract rather than the identity WithAttrs and WithGroup the
// private recorders used, because a helper shared by every suite in the tree cannot know which of
// them will one day build a logger with attributes on it: a recorder that dropped them would
// report a record as missing an attribute that the real handler prints.
type recordingHandler struct {
	capture *SlogCapture
	prefix  []slog.Attr // attributes from WithAttrs, keys already qualified
	groups  []string    // the open group path, applied to the record's own attributes
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, record slog.Record) error {
	attrs := append([]slog.Attr(nil), h.prefix...)
	record.Attrs(func(attr slog.Attr) bool {
		attrs = appendFlattened(attrs, h.groups, attr)
		return true
	})
	h.capture.append(capturedEntry{
		time:    record.Time,
		level:   record.Level,
		message: record.Message,
		attrs:   attrs,
	})
	return nil
}

func (h *recordingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	prefix := append([]slog.Attr(nil), h.prefix...)
	for _, attr := range attrs {
		prefix = appendFlattened(prefix, h.groups, attr)
	}
	return &recordingHandler{capture: h.capture, prefix: prefix, groups: h.groups}
}

func (h *recordingHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		// slog.Handler's contract: an empty group name is a no-op.
		return h
	}
	groups := append(append([]string(nil), h.groups...), name)
	return &recordingHandler{capture: h.capture, prefix: h.prefix, groups: groups}
}

// appendFlattened adds one attribute under the open group path, resolving it first.
//
// slog's contract for a group attribute is followed as written: an empty group is dropped, and a
// group with an empty key is inlined at the level it was written rather than qualifying anything.
func appendFlattened(into []slog.Attr, groups []string, attr slog.Attr) []slog.Attr {
	value := attr.Value.Resolve()
	if value.Kind() == slog.KindGroup {
		members := value.Group()
		if len(members) == 0 {
			return into
		}
		nested := groups
		if attr.Key != "" {
			nested = append(append([]string(nil), groups...), attr.Key)
		}
		for _, member := range members {
			into = appendFlattened(into, nested, member)
		}
		return into
	}
	if attr.Equal(slog.Attr{}) {
		// slog's contract: an empty attribute is dropped.
		return into
	}
	key := attr.Key
	if len(groups) > 0 {
		key = strings.Join(groups, ".") + "." + key
	}
	return append(into, slog.Attr{Key: key, Value: value})
}
