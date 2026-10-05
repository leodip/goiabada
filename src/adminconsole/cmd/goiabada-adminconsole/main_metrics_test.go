package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The metrics listener at the process (#400 decisions 3 and 6): main reads the three settings,
// Start serves the listener beside the others, a scrape reaches it and reports the families main
// composed, the calls the clients main built made to the auth server among them, and on SIGTERM it
// drains with the others. The child is the real main; the auth server is a stub this test serves.

// metricsChild is a running main configured for the metrics listener.
type metricsChild struct {
	cmd     *exec.Cmd
	records chan map[string]any
	done    chan struct{}
}

// startMetricsChild starts main with the http listener and the metrics listener on loopback, the
// latter on metricsPort, against the auth server at authServerURL, and delivers each record it
// writes as it writes it. enabled is the value of the metrics setting, and an empty one leaves the
// setting out of the environment.
func startMetricsChild(t *testing.T, ctx context.Context, authServerURL string, httpPort, metricsPort int, enabled string) *metricsChild {
	t.Helper()

	cmd := exec.CommandContext(ctx, os.Args[0])
	cmd.Env = []string{
		runMainMarker + "=1",
		"GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY=" + strings.Repeat("b1", 64),
		"GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY=" + strings.Repeat("b2", 32),
		"GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET=process-test-secret",
		"GOIABADA_ADMINCONSOLE_LOG_FORMAT=json",
		"GOIABADA_AUTHSERVER_BASEURL=" + authServerURL,
		"GOIABADA_ADMINCONSOLE_BASEURL=http://127.0.0.1:" + strconv.Itoa(httpPort),
		"GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTP=127.0.0.1",
		"GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP=" + strconv.Itoa(httpPort),
		"GOIABADA_ADMINCONSOLE_LISTEN_HOST_METRICS=127.0.0.1",
		"GOIABADA_ADMINCONSOLE_LISTEN_PORT_METRICS=" + strconv.Itoa(metricsPort),
	}
	if enabled != "" {
		cmd.Env = append(cmd.Env, "GOIABADA_ADMINCONSOLE_METRICS_ENABLED="+enabled)
	}
	stderr, err := cmd.StderrPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())

	child := &metricsChild{cmd: cmd, records: make(chan map[string]any, 1024), done: make(chan struct{})}
	go func() {
		defer close(child.done)
		defer close(child.records)
		scanner := bufio.NewScanner(stderr)
		scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
		for scanner.Scan() {
			var record map[string]any
			if json.Unmarshal(scanner.Bytes(), &record) != nil {
				record = map[string]any{"msg": "(not a record) " + scanner.Text()}
			}
			child.records <- record
		}
	}()
	return child
}

// wait answers the child's exit code and every record it wrote.
func (c *metricsChild) wait(t *testing.T, ctx context.Context) (int, []map[string]any) {
	t.Helper()

	var records []map[string]any
	for record := range c.records {
		records = append(records, record)
	}
	<-c.done
	err := c.cmd.Wait()
	if ctx.Err() != nil {
		t.Fatalf("main did not exit within %s\n%s", mainProcessBound, dumpRecords(records))
	}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0, records
	case errors.As(err, &exitErr):
		return exitErr.ExitCode(), records
	default:
		t.Fatalf("running main: %v\n%s", err, dumpRecords(records))
		return -1, nil
	}
}

func dumpRecords(records []map[string]any) string {
	var b strings.Builder
	for _, r := range records {
		fmt.Fprintf(&b, "%v\n", r)
	}
	return b.String()
}

func recordNamed(records []map[string]any, msg string) map[string]any {
	for _, r := range records {
		if r["msg"] == msg {
			return r
		}
	}
	return nil
}

func indexOfRecord(records []map[string]any, msg string) int {
	for i, r := range records {
		if r["msg"] == msg {
			return i
		}
	}
	return -1
}

// freePort is a loopback port nothing listens on as it returns.
func freePort(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port
}

// getWhenUp sends a GET to url until something answers it, for as long as ctx allows, following no
// redirect.
func getWhenUp(t *testing.T, ctx context.Context, url string) (int, string, string) {
	t.Helper()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for {
		resp, err := client.Get(url)
		if err == nil {
			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			require.NoError(t, readErr)
			return resp.StatusCode, resp.Header.Get("Content-Type"), string(body)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("nothing answered %s: %v", url, err)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// stubAuthServer answers the public settings and a client credentials grant, and refuses the
// browser-session endpoint, so a console page that saves a session reaches three of the clients
// main builds: the settings client, the token client and the session backend.
func stubAuthServer(t *testing.T) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/public/settings":
			_, _ = w.Write([]byte(`{"appName":"Goiabada","issuer":"https://auth.example.test","uiTheme":"light","smtpEnabled":false}`))
		case "/auth/token":
			_, _ = w.Write([]byte(`{"access_token":"a-session-token","token_type":"Bearer","expires_in":300}`))
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func TestMain_ServesMetricsOnTheirOwnListenerAndDrainsIt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), mainProcessBound)
	defer cancel()

	authServer := stubAuthServer(t)
	httpPort, metricsPort := freePort(t), freePort(t)
	child := startMetricsChild(t, ctx, authServer.URL, httpPort, metricsPort, "true")
	metricsURL := "http://127.0.0.1:" + strconv.Itoa(metricsPort) + "/metrics"

	status, contentType, body := getWhenUp(t, ctx, metricsURL)
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, "text/plain; version=0.0.4; charset=utf-8", contentType)

	// An administrator with no session reaching the console is sent to sign in, which saves the
	// sign-in's state in a new session: the settings, then a token for the session endpoint, then
	// the session endpoint itself, which this auth server refuses.
	getWhenUp(t, ctx, "http://127.0.0.1:"+strconv.Itoa(httpPort)+"/admin/users")

	status, _, body = getWhenUp(t, ctx, "http://127.0.0.1:"+strconv.Itoa(httpPort)+"/metrics")
	assert.Equal(t, http.StatusNotFound, status, "the main listener serves no metrics")
	assert.NotContains(t, body, "goiabada_build_info")

	_, _, exposition := getWhenUp(t, ctx, metricsURL)
	for _, family := range []string{
		"# TYPE goiabada_http_requests_total counter",
		"# TYPE goiabada_http_request_duration_seconds histogram",
		"# TYPE goiabada_upstream_requests_total counter",
		"# TYPE goiabada_upstream_request_duration_seconds histogram",
		"# TYPE goiabada_settings_cache_requests_total counter",
		"# TYPE goiabada_build_info gauge",
		"# TYPE go_goroutines gauge",
		"# TYPE go_memstats_heap_inuse_bytes gauge",
	} {
		assert.Contains(t, exposition, family+"\n", "main registers every family the catalog names")
	}
	for _, line := range []string{
		`goiabada_upstream_requests_total{target="settings",status="200"} 1`,
		`goiabada_upstream_requests_total{target="token",status="200"} 1`,
		`goiabada_upstream_requests_total{target="sessions",status="503"} 1`,
		`goiabada_settings_cache_requests_total{result="miss"} 1`,
	} {
		assert.Contains(t, exposition, line+"\n")
	}

	require.NoError(t, child.cmd.Process.Signal(syscall.SIGTERM))
	code, records := child.wait(t, ctx)

	require.Equalf(t, 0, code, "a drained stop exits 0\n%s", dumpRecords(records))
	assert.Less(t, indexOfRecord(records, "listeners drained"), indexOfRecord(records, "admin console stopped"))
	configured := recordNamed(records, "metrics listener configuration")
	require.NotNilf(t, configured, "the listener's configuration is recorded as the others' is\n%s", dumpRecords(records))
	assert.Equal(t, true, configured["enabled"])
	assert.Equal(t, "127.0.0.1", configured["host"])
	assert.Equal(t, float64(metricsPort), configured["port"])

	_, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(metricsPort), time.Second)
	assert.Error(t, err, "the metrics listener is closed once the process has stopped")
}

// A metrics port the process cannot bind stops it as the other listeners' do: the error names the
// address, main writes the one record for it and exits 1.
func TestMain_AMetricsPortItCannotBindStopsTheConsole(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), mainProcessBound)
	defer cancel()

	taken, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = taken.Close() }()
	takenPort := taken.Addr().(*net.TCPAddr).Port

	child := startMetricsChild(t, ctx, stubAuthServer(t).URL, freePort(t), takenPort, "true")
	code, records := child.wait(t, ctx)

	require.Equalf(t, 1, code, "\n%s", dumpRecords(records))
	stopped := recordNamed(records, "the admin console stopped on an error")
	require.NotNilf(t, stopped, "\n%s", dumpRecords(records))
	assert.Contains(t, stopped["error"], "127.0.0.1:"+strconv.Itoa(takenPort), "the failure names the metrics listener's address")
}

// Off unless enabled (#400 decision 3): with the setting left out, or set to false, the process
// starts no metrics listener at all. The configured metrics port is held by a server of this
// test's own, so a process that tried to bind it would stop on the error above, and a scrape of
// that port reaches this test's server rather than the process's registry.
func TestMain_MetricsOffLeavesTheMetricsPortAlone(t *testing.T) {
	for name, enabled := range map[string]string{"omitted": "", "false": "false"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), mainProcessBound)
			defer cancel()

			taken, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			holder := &http.Server{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusTeapot)
				}),
				ReadHeaderTimeout: time.Second,
			}
			go func() { _ = holder.Serve(taken) }()
			defer func() { _ = holder.Close() }()
			takenPort := taken.Addr().(*net.TCPAddr).Port

			httpPort := freePort(t)
			child := startMetricsChild(t, ctx, stubAuthServer(t).URL, httpPort, takenPort, enabled)

			// A process that exits, as one that tried to bind the held port does, ends the wait at
			// once rather than at the bound.
			up, upCancel := context.WithCancel(ctx)
			defer upCancel()
			go func() {
				select {
				case <-child.done:
				case <-up.Done():
				}
				upCancel()
			}()

			status, _, body := getWhenUp(t, up, "http://127.0.0.1:"+strconv.Itoa(httpPort)+"/health")
			require.Equal(t, http.StatusOK, status, "the main listener answers: %s", body)

			status, _, body = getWhenUp(t, up, "http://127.0.0.1:"+strconv.Itoa(takenPort)+"/metrics")
			assert.Equal(t, http.StatusTeapot, status, "the metrics port is still this test's")
			assert.NotContains(t, body, "goiabada_build_info")

			require.NoError(t, child.cmd.Process.Signal(syscall.SIGTERM))
			code, records := child.wait(t, ctx)

			require.Equalf(t, 0, code, "a process that never binds the metrics port stops cleanly\n%s", dumpRecords(records))
			configured := recordNamed(records, "metrics listener configuration")
			require.NotNilf(t, configured, "\n%s", dumpRecords(records))
			assert.Equal(t, false, configured["enabled"])
			assert.Nilf(t, recordNamed(records, "starting the metrics listener"), "\n%s", dumpRecords(records))
		})
	}
}
