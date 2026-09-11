// Package logging owns the slog handler both servers install at startup, and
// the bound every client-chosen scalar attribute passes through before it
// reaches a record (#320).
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/leodip/goiabada/core/errs"
)

// Install builds the process-wide handler from the two configured settings and
// makes it the slog default. An unrecognised level or format is refused before
// anything is installed, so a deployment that misspells one gets a startup
// failure naming the value rather than a silently different log stream (#320).
func Install(level, format string) error {
	handler, err := newHandler(os.Stderr, level, format)
	if err != nil {
		return err
	}
	slog.SetDefault(slog.New(handler))
	return nil
}

// newHandler is Install without the process-global effect, which is what makes
// the handler testable: every case in logging_test.go drives it with a buffer.
func newHandler(w io.Writer, level, format string) (slog.Handler, error) {
	parsedLevel, err := parseLevel(level)
	if err != nil {
		return nil, err
	}

	switch format {
	case "text":
		// Both text handlers already print an error value with %+v, so an errs
		// stack reaches the log with no help.
		return WrapRequestID(slog.NewTextHandler(w, &slog.HandlerOptions{Level: parsedLevel})), nil
	case "json":
		return WrapRequestID(slog.NewJSONHandler(w, &slog.HandlerOptions{
			Level:       parsedLevel,
			ReplaceAttr: errorWithStack,
		})), nil
	}
	return nil, errs.Errorf("log format %q is not one of text, json", format)
}

func parseLevel(level string) (slog.Level, error) {
	switch level {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, errs.Errorf("log level %q is not one of debug, info, warn, error", level)
}

// errorWithStack renders an error attribute the way the text handlers do.
//
// It exists because slog's JSON handler writes err.Error() for an error value,
// which drops the stack core/errs captured at the origin: the same record that
// carries a full trace under text carries "wrapped: boom" and nothing else
// under JSON. Remove this and a JSON deployment loses every stack in the
// product. The newlines are folded because a JSON string holding them is
// legible to a collector and not to a person reading it raw (#320, #279).
func errorWithStack(_ []string, a slog.Attr) slog.Attr {
	if err, ok := a.Value.Any().(error); ok {
		return slog.String(a.Key, strings.ReplaceAll(fmt.Sprintf("%+v", err), "\n\t", " "))
	}
	return a
}

// WrapRequestID returns h with chi's request id appended to every record logged
// with a context that carries one, so no call site has to name it.
//
// It is exported because testutil.CaptureSlog wraps its recorder with it: a
// test asserting on request_id has to exercise the same injection the servers
// run, not a second copy of it.
func WrapRequestID(h slog.Handler) slog.Handler {
	return &requestIDHandler{base: h, delegate: h}
}

// handlerCall records one WithAttrs or WithGroup made on a requestIDHandler.
// Exactly one of attrs and group is set.
type handlerCall struct {
	attrs []slog.Attr
	group string
}

// requestIDHandler injects request_id at the record root.
//
// Keeping the ungrouped delegate is the whole design. slog's contract qualifies
// every attribute a handler is given after WithGroup by that group, so a
// wrapper that simply re-wrapped the grouped handler would write the request id
// as operation.request_id, under whatever group the caller happened to open,
// and a collector correlating on request_id would stop finding it. So the
// wrapper keeps the base handler and the ordered calls made on it, and once a
// group is open it applies the id to the base first and replays the calls on
// the result. Production opens no groups (the slog lint refuses slog.With and
// slog.Default outside this package), so the replay path is the contract kept
// honest rather than a per-record cost (#320).
type requestIDHandler struct {
	base     slog.Handler
	delegate slog.Handler // base with calls already replayed, for the common path
	calls    []handlerCall
	grouped  bool
}

func (h *requestIDHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.base.Enabled(ctx, level)
}

func (h *requestIDHandler) Handle(ctx context.Context, r slog.Record) error {
	requestId := chimiddleware.GetReqID(ctx)
	if requestId == "" {
		return h.delegate.Handle(ctx, r)
	}

	// Through FieldForLog because chi's RequestID middleware adopts an inbound
	// X-Request-Id header verbatim, so this string is client-chosen on every
	// request that supplies one (#159).
	attr := slog.String("request_id", FieldForLog(requestId))
	if !h.grouped {
		r.AddAttrs(attr)
		return h.delegate.Handle(ctx, r)
	}
	return h.replay(h.base.WithAttrs([]slog.Attr{attr})).Handle(ctx, r)
}

func (h *requestIDHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	return &requestIDHandler{
		base:     h.base,
		delegate: h.delegate.WithAttrs(attrs),
		calls:    h.record(handlerCall{attrs: attrs}),
		grouped:  h.grouped,
	}
}

func (h *requestIDHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		// slog.Handler's contract: an empty group name is a no-op.
		return h
	}
	return &requestIDHandler{
		base:     h.base,
		delegate: h.delegate.WithGroup(name),
		calls:    h.record(handlerCall{group: name}),
		grouped:  true,
	}
}

// record appends call to a copy of h.calls. A copy rather than an append in
// place because two WithGroup calls on the same handler must not overwrite each
// other's entry in a shared backing array.
func (h *requestIDHandler) record(call handlerCall) []handlerCall {
	calls := make([]handlerCall, len(h.calls), len(h.calls)+1)
	copy(calls, h.calls)
	return append(calls, call)
}

func (h *requestIDHandler) replay(handler slog.Handler) slog.Handler {
	for _, call := range h.calls {
		if call.group != "" {
			handler = handler.WithGroup(call.group)
			continue
		}
		handler = handler.WithAttrs(call.attrs)
	}
	return handler
}
