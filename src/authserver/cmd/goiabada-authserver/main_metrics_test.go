package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The metrics listener at the process (#400 decision 3): main reads the three settings, Start
// serves the listener beside the others, a scrape reaches it, and on SIGTERM it drains with them.
// The child is the real main over a fresh SQLite file it migrates and seeds.

// metricsChild is a running main configured for the metrics listener.
type metricsChild struct {
	cmd     *exec.Cmd
	records chan map[string]any
	done    chan struct{}
}

// startMetricsChild starts main with the http listener and the metrics listener on loopback, the
// latter on metricsPort, and delivers each record it writes as it writes it. enabled is the value
// of the metrics setting, and an empty one leaves the setting out of the environment.
func startMetricsChild(t *testing.T, ctx context.Context, httpPort, metricsPort int, enabled string) *metricsChild {
	t.Helper()

	env := []string{
		runMainMarker + "=1",
		"GOIABADA_DB_TYPE=sqlite",
		"GOIABADA_DB_DSN=file:" + filepath.Join(t.TempDir(), "m.db"),
		"GOIABADA_AUTHSERVER_LOG_FORMAT=json",
		"GOIABADA_AES_ENCRYPTION_KEY=" + strings.Repeat("ab", 32),
		"GOIABADA_ADMIN_EMAIL=admin@example.com",
		"GOIABADA_ADMIN_PASSWORD=a-long-enough-password-for-the-seed",
		"GOIABADA_AUTHSERVER_LISTEN_HOST_HTTP=127.0.0.1",
		"GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP=" + strconv.Itoa(httpPort),
		"GOIABADA_AUTHSERVER_LISTEN_HOST_METRICS=127.0.0.1",
		"GOIABADA_AUTHSERVER_LISTEN_PORT_METRICS=" + strconv.Itoa(metricsPort),
	}
	if enabled != "" {
		env = append(env, "GOIABADA_AUTHSERVER_METRICS_ENABLED="+enabled)
	}
	cmd := exec.CommandContext(ctx, os.Args[0])
	cmd.Env = append(env, singleStepEnv...)
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

// wait answers the child's exit code and every record it wrote that nothing has read yet.
func (c *metricsChild) wait(t *testing.T, ctx context.Context) (int, []map[string]any) {
	t.Helper()

	var records []map[string]any
	for record := range c.records {
		records = append(records, record)
	}
	<-c.done
	err := c.cmd.Wait()
	if ctx.Err() != nil {
		t.Fatalf("main did not exit within %s\n%s", mainProcessBound, dump(records))
	}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0, records
	case errors.As(err, &exitErr):
		return exitErr.ExitCode(), records
	default:
		t.Fatalf("running main: %v\n%s", err, dump(records))
		return -1, nil
	}
}

// getWhenUp sends a GET to url until something answers it, for as long as ctx allows.
func getWhenUp(t *testing.T, ctx context.Context, url string) (int, string, string) {
	t.Helper()

	for {
		resp, err := http.Get(url)
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

func TestMain_ServesMetricsOnTheirOwnListenerAndDrainsIt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), mainProcessBound)
	defer cancel()

	httpPort, metricsPort := freePort(t), freePort(t)
	child := startMetricsChild(t, ctx, httpPort, metricsPort, "true")

	status, contentType, body := getWhenUp(t, ctx, "http://127.0.0.1:"+strconv.Itoa(metricsPort)+"/metrics")
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, "text/plain; version=0.0.4; charset=utf-8", contentType)
	assert.Contains(t, body, "# TYPE goiabada_build_info gauge\n")

	status, _, body = getWhenUp(t, ctx, "http://127.0.0.1:"+strconv.Itoa(httpPort)+"/metrics")
	assert.Equal(t, http.StatusNotFound, status, "the main listener serves no metrics")
	assert.NotContains(t, body, "goiabada_build_info")

	require.NoError(t, child.cmd.Process.Signal(syscall.SIGTERM))
	code, records := child.wait(t, ctx)

	require.Equalf(t, 0, code, "a drained stop exits 0\n%s", dump(records))
	messages := messagesOf(records)
	assert.Less(t, indexOf(messages, "listeners drained"), indexOf(messages, "auth server stopped"))
	configured := recordNamed(records, "metrics listener configuration")
	require.NotNilf(t, configured, "the listener's configuration is recorded as the others' is\n%s", dump(records))
	assert.Equal(t, true, configured["enabled"])
	assert.Equal(t, "127.0.0.1", configured["host"])
	assert.Equal(t, float64(metricsPort), configured["port"])

	_, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(metricsPort), time.Second)
	assert.Error(t, err, "the metrics listener is closed once the process has stopped")
}

// A metrics port the process cannot bind stops it as the other listeners' do: the error names the
// address, main writes the one record for it and exits 1.
func TestMain_AMetricsPortItCannotBindStopsTheServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), mainProcessBound)
	defer cancel()

	taken, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = taken.Close() }()
	takenPort := taken.Addr().(*net.TCPAddr).Port

	child := startMetricsChild(t, ctx, freePort(t), takenPort, "true")
	code, records := child.wait(t, ctx)

	require.Equalf(t, 1, code, "\n%s", dump(records))
	stopped := recordNamed(records, "the auth server stopped on an error")
	require.NotNilf(t, stopped, "\n%s", dump(records))
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
			child := startMetricsChild(t, ctx, httpPort, takenPort, enabled)

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

			require.Equalf(t, 0, code, "a process that never binds the metrics port stops cleanly\n%s", dump(records))
			configured := recordNamed(records, "metrics listener configuration")
			require.NotNilf(t, configured, "\n%s", dump(records))
			assert.Equal(t, false, configured["enabled"])
			assert.Nilf(t, recordNamed(records, "starting the metrics listener"), "\n%s", dump(records))
		})
	}
}
