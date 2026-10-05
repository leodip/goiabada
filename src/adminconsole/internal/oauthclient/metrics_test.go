package oauthclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/oauthclient/oauthclienttest"
	"github.com/leodip/goiabada/adminconsole/internal/upstreammetrics"
	"github.com/leodip/goiabada/core/metrics"
)

// The token client and the JWKS fetch share one HTTP client in main (#441), and each records its
// own calls under its own target, as a scrape reports them (#400 decision 6): a grant is a token
// call and a fetch of /certs a jwks call, though the two go out through the same client.
func TestTokenClientAndJWKSFetch_SharingAClientRecordUnderTheirOwnTargets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/certs":
			_, _ = w.Write([]byte(`{"keys":[]}`))
		case "/auth/token":
			_, _ = w.Write([]byte(`{"access_token":"a","token_type":"Bearer","expires_in":300}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	reg := metrics.NewRegistry()
	upstream := upstreammetrics.Register(reg)
	shared := NewAuthServerHTTPClient()
	tokenClient := NewTokenClient(TokenEndpointURL(server.URL), "ci", "cs", shared, upstream)
	parser := NewJWKSTokenParser(server.URL, shared, upstream, oauthclienttest.ClientID,
		oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	_, err := tokenClient.ClientCredentials(context.Background(), "authserver:manage")
	require.NoError(t, err)
	_, err = tokenClient.ClientCredentials(context.Background(), "authserver:manage")
	require.NoError(t, err)
	require.NoError(t, parser.refreshJwks(context.Background()))

	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	exposition := rec.Body.String()
	assert.Contains(t, exposition, `goiabada_upstream_requests_total{target="token",status="200"} 2`+"\n")
	assert.Contains(t, exposition, `goiabada_upstream_requests_total{target="jwks",status="200"} 1`+"\n")
	assert.Contains(t, exposition, `goiabada_upstream_request_duration_seconds_count{target="token"} 2`+"\n")
	assert.Contains(t, exposition, `goiabada_upstream_request_duration_seconds_count{target="jwks"} 1`+"\n")
	assert.Nil(t, shared.Transport, "the shared client is wrapped in copies, never itself")
}
