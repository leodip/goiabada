package main

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The start-up check of the console's own client at the process (#542): main asks before it
// listens, stops on a refusal with the record that names the secret, and while the auth server is
// not answering it waits, listening on nothing, and a SIGTERM ends the wait as it ends a run.

// A listener is configured on a free port, so a main that skipped the check would serve rather
// than exit, and the case would fail on the harness's bound.
func TestMain_AClientSecretTheAuthServerRefusesStopsTheStart(t *testing.T) {
	var requests atomic.Int32
	authServer := tokenEndpoint(t, &requests, http.StatusUnauthorized)

	code, stderr := runMainProcess(t, []string{
		"GOIABADA_AUTHSERVER_BASEURL=" + authServer.URL,
		"GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTP=127.0.0.1",
		"GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP=" + strconv.Itoa(freePort(t)),
	})

	require.Equal(t, 1, code, "stderr: %s", stderr)
	assert.Contains(t, stderr, "the auth server does not accept the admin console's client secret, so the admin console cannot start")
	assert.Contains(t, stderr, "set GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET to the secret admin-console-client has")
	assert.Contains(t, stderr, "invalid_client: Client authentication failed", "the auth server's own reason rides in the error")
	assert.NotContains(t, stderr, "starting the http listener", "it stops before it listens")
	assert.Equal(t, int32(1), requests.Load(), "a refusal is not asked again")
}

func TestMain_WaitsForTheAuthServerAndAStopEndsTheWait(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), mainProcessBound)
	defer cancel()

	var requests atomic.Int32
	authServer := tokenEndpoint(t, &requests, http.StatusServiceUnavailable)
	ports := freePorts(t, 2)
	child := startMetricsChild(t, ctx, authServer.URL, ports[0], ports[1], "")

	const waiting = "waiting for the auth server to issue the admin console's token"
	var records []map[string]any
	for record := range child.records {
		records = append(records, record)
		if record["msg"] == waiting {
			break
		}
	}
	require.NotNilf(t, recordNamed(records, waiting), "the child never waited\n%s", dumpRecords(records))
	assert.Contains(t, recordNamed(records, waiting)["error"], "answered 503")

	_, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(ports[0]), time.Second)
	require.Error(t, err, "nothing listens while the console waits, so no probe calls it ready")

	require.NoError(t, child.cmd.Process.Signal(syscall.SIGTERM))
	code, rest := child.wait(t, ctx)
	records = append(records, rest...)

	require.Equalf(t, 0, code, "a stop while waiting is a stop, not a failure\n%s", dumpRecords(records))
	assert.NotNilf(t, recordNamed(records, "admin console stopped"), "\n%s", dumpRecords(records))
	assert.Nil(t, recordNamed(records, "starting the http listener"))
}
