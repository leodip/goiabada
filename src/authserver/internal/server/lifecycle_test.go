package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The lifecycle Start runs once its listeners are built: serve until the process is told to stop or
// a listener fails, then drain every listener and only then stop the worker (#426, #390 R16). Start
// itself cannot be driven to that point here, since its servers listen on the configured ports, so
// these cases hand serveAndDrain the same newHTTPServer on an ephemeral port.

// heldHandler answers only once release is closed, and says when a request has reached it and when
// it has written its answer.
type heldHandler struct {
	entered  chan struct{}
	release  chan struct{}
	answered atomic.Bool
}

func newHeldHandler() *heldHandler {
	return &heldHandler{entered: make(chan struct{}), release: make(chan struct{})}
}

func (h *heldHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	close(h.entered)
	<-h.release
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("the held response"))
	h.answered.Store(true)
}

// servedOnLoopback is the listener Start builds, served on an ephemeral loopback port.
func servedOnLoopback(t *testing.T, handler http.Handler) listener {
	t.Helper()

	srv := newHTTPServer("127.0.0.1", 0, handler)
	ln, err := net.Listen("tcp", srv.Addr)
	require.NoError(t, err)
	srv.Addr = ln.Addr().String()
	t.Cleanup(func() { _ = srv.Close() })

	return listener{server: srv, serve: func() error { return srv.Serve(ln) }}
}

type clientResult struct {
	status int
	body   string
	err    error
}

// requestInBackground sends one GET and delivers what came back.
func requestInBackground(addr string) <-chan clientResult {
	result := make(chan clientResult, 1)
	go func() {
		client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
		resp, err := client.Get("http://" + addr + "/")
		if err != nil {
			result <- clientResult{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		result <- clientResult{status: resp.StatusCode, body: string(body), err: err}
	}()
	return result
}

func waitFor[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		var zero T
		return zero
	}
}

func messages(records []testutil.CapturedRecord) []string {
	var got []string
	for _, record := range records {
		got = append(got, record.Message)
	}
	return got
}

func assertNoErrorRecord(t *testing.T, records []testutil.CapturedRecord) {
	t.Helper()
	for _, record := range records {
		assert.Less(t, record.Level, slog.LevelError,
			"%q is an Error record: main writes the one record for what Start returns", record.Message)
	}
}

// A cancellation, which is what SIGTERM becomes in main, waits for the request in flight: its client
// gets the whole answer, the function returns nil only after that, and the worker stops only after
// the drain. Before #426 the console cut such a request off, and the auth server's drain lived in a
// method nothing could reach without the configured ports.
func TestServeAndDrain_CancellationWaitsForTheHeldRequest(t *testing.T) {
	logs := testutil.CaptureSlog(t)

	held := newHeldHandler()
	served := servedOnLoopback(t, held)

	// The first call is the one recorded, so a stop moved ahead of the drain is not hidden by a
	// second, correctly placed one.
	var workerStops int
	var recordsWhenTheWorkerStopped []string
	var answeredWhenTheWorkerStopped bool
	afterDrain := func() {
		workerStops++
		if workerStops == 1 {
			recordsWhenTheWorkerStopped = messages(logs.Records())
			answeredWhenTheWorkerStopped = held.answered.Load()
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	returned := make(chan error, 1)
	go func() { returned <- serveAndDrain(ctx, []listener{served}, afterDrain) }()

	response := requestInBackground(served.server.Addr)
	waitFor(t, held.entered, "the request to reach the handler")

	cancel()

	select {
	case err := <-returned:
		t.Fatalf("serveAndDrain returned (%v) while a request was still in flight", err)
	case <-time.After(200 * time.Millisecond):
	}

	close(held.release)

	got := waitFor(t, response, "the held response")
	require.NoError(t, got.err, "the request in flight must be answered, not cut off")
	assert.Equal(t, http.StatusOK, got.status)
	assert.Equal(t, "the held response", got.body)

	assert.NoError(t, waitFor(t, returned, "serveAndDrain to return"),
		"a cancellation is a clean stop, and http.ErrServerClosed from the drained listener is not a failure")

	assert.Equal(t, 1, workerStops, "the worker is stopped once")
	assert.True(t, answeredWhenTheWorkerStopped, "the worker must stop only after the listeners have drained")
	assert.Equal(t, []string{"shutdown signal received", "listeners drained"}, recordsWhenTheWorkerStopped,
		"the worker stops between the drain and the end of the shutdown")

	records := logs.Records()
	assert.Equal(t, []string{"shutdown signal received", "listeners drained", "shutdown complete"}, messages(records))
	assertNoErrorRecord(t, records)
}

// A listener that fails is no reason to cut off what the other one is answering: the function drains
// the healthy listener, stops the worker, and only then returns the failure. The failure is returned
// rather than logged, and is never http.ErrServerClosed, which the healthy listener's serve call
// returns once it is drained.
func TestServeAndDrain_AFailedListenerDrainsTheOtherFirst(t *testing.T) {
	logs := testutil.CaptureSlog(t)

	held := newHeldHandler()
	healthy := servedOnLoopback(t, held)

	errBind := errors.New("the address is already in use")
	fail := make(chan struct{})
	failing := listener{
		server: newHTTPServer("127.0.0.1", 0, nil),
		serve: func() error {
			<-fail
			return errBind
		},
	}

	var workerStops atomic.Int32
	returned := make(chan error, 1)
	go func() {
		returned <- serveAndDrain(context.Background(), []listener{healthy, failing}, func() { workerStops.Add(1) })
	}()

	response := requestInBackground(healthy.server.Addr)
	waitFor(t, held.entered, "the request to reach the handler")

	close(fail)

	select {
	case err := <-returned:
		t.Fatalf("serveAndDrain returned (%v) while the other listener was still answering", err)
	case <-time.After(200 * time.Millisecond):
	}

	close(held.release)

	got := waitFor(t, response, "the held response")
	require.NoError(t, got.err, "the healthy listener's request must be answered, not cut off")
	assert.Equal(t, http.StatusOK, got.status)

	err := waitFor(t, returned, "serveAndDrain to return")
	require.Error(t, err)
	assert.ErrorIs(t, err, errBind, "the listener's own failure is what main reports")
	assert.NotErrorIs(t, err, http.ErrServerClosed, "a drained listener is not a failure")
	assert.Contains(t, err.Error(), "127.0.0.1:0", "the failure names the listener it came from")
	assert.Equal(t, int32(1), workerStops.Load(), "the worker stops, once, on the failure path too")

	records := logs.Records()
	assert.Equal(t, []string{"listeners drained", "shutdown complete"}, messages(records),
		"no signal arrived, so none is recorded")
	assertNoErrorRecord(t, records)
}

// With no listener configured Start refuses before it starts the worker or builds a route, and says
// so as a returned error, which main logs once before it exits (#426, #390 R16). The Server here has
// no router and no worker, so reaching either would panic rather than return.
func TestStart_WithNoListenerRefusesBeforeStartingAnything(t *testing.T) {
	logs := testutil.CaptureSlog(t)

	cfg := config.GetAuthServer()
	previousHTTPS, previousHTTP := cfg.ListenHostHttps, cfg.ListenHostHttp
	t.Cleanup(func() { cfg.ListenHostHttps, cfg.ListenHostHttp = previousHTTPS, previousHTTP })
	cfg.ListenHostHttps, cfg.ListenHostHttp = "", ""

	s := &Server{}
	err := s.Start(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no listener is enabled")
	assert.Contains(t, err.Error(), "auth server", "the refusal names the binary it stops")
	assertNoErrorRecord(t, logs.Records())
}
