package integration

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A self-registered client's back-channel logout URI reaches only a public address (#784 decision
// 7): the auth server checks the address it dials, after resolving the name, and refuses loopback
// here. The receiver is an https server on 127.0.0.1, which an administrator's client would reach;
// the delivery to the self-registered client never gets to it, is not retried, and is audited and
// counted as blocked, whoever set the URI.

// TestBackchannelLogout_ASelfRegisteredClientIsNotSentToAnInternalAddress registers a client
// through dynamic client registration with an https URI on loopback, by its address or by a name
// resolving to it, or has an administrator set one on it later, and ends the user's session the
// client was on.
func TestBackchannelLogout_ASelfRegisteredClientIsNotSentToAnInternalAddress(t *testing.T) {
	requireDatabaseAuditLogs(t)
	enableDCR(t)
	adminToken, adminClient := createAdminClientWithToken(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, adminClient.Id) })

	var reached atomic.Int32
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(receiver.Close)
	_, port, err := net.SplitHostPort(receiver.Listener.Addr().String())
	require.NoError(t, err)

	tests := []struct {
		name          string
		registeredURI string
		// adminURI, when set, is what an administrator sets on the client after it registered.
		adminURI string
	}{
		{name: "registered on a loopback address", registeredURI: "https://127.0.0.1:" + port + "/backchannel-logout"},
		{name: "registered on a name resolving to loopback", registeredURI: "https://localhost:" + port + "/backchannel-logout"},
		{name: "set on loopback by an administrator later", registeredURI: "https://dcr-guard.example.com/backchannel-logout",
			adminURI: "https://127.0.0.1:" + port + "/backchannel-logout"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, members := postDCRBody(t, `{"client_name":"Guarded Registration",`+
				`"redirect_uris":["https://dcr-guard.example.com/callback"],`+
				`"backchannel_logout_uri":"`+tc.registeredURI+`"}`)
			require.Equal(t, http.StatusCreated, status, "%v", members)
			var identifier string
			require.NoError(t, json.Unmarshal(members["client_id"], &identifier))
			client, err := database.GetClientByClientIdentifier(context.Background(), nil, identifier)
			require.NoError(t, err)
			require.NotNil(t, client)
			t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
			if tc.adminURI != "" {
				status, body, _ := saveBackchannelLogout(t, adminToken, client.Id, backchannelLogoutBody(tc.adminURI, false))
				require.Equal(t, http.StatusOK, status, "%v", body)
			}

			accessToken, user := getUserAccessTokenWithAccountScope(t)
			session := createTestUserSession(t, user.Id, fake.UUID())
			onSession(t, session, client)
			blockedBefore := sampleValue(t, scrapeMetrics(t), `goiabada_backchannel_logout_deliveries_total{outcome="blocked"}`)
			reachedBefore := reached.Load()

			resp, requestId := sendAdminRequest(t, accessToken, http.MethodDelete,
				"/api/v1/account/sessions/"+strconv.FormatInt(session.Id, 10), nil)
			_ = resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)

			_, details := sentLogoutTokenRow(t, requestId, 10*time.Second)
			assert.Equal(t, "blocked", details["outcome"])
			assert.InDelta(t, 1, details["attempts"], 0, "a blocked address is not tried again")
			assert.InDelta(t, float64(client.Id), details["client_id"], 0)
			assert.Equal(t, session.SessionIdentifier, details["session_identifier"])

			assert.InDelta(t, blockedBefore+1,
				sampleValue(t, scrapeMetrics(t), `goiabada_backchannel_logout_deliveries_total{outcome="blocked"}`), 0)
			assert.Equal(t, reachedBefore, reached.Load(), "nothing reaches the internal address")
		})
	}
}
