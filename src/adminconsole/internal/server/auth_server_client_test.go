package server

import (
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The JWKS fetch is the reason this is worth a case of its own. Both grants
// build their own ten second deadline out of the request's context, so the
// client's timeout is redundant defence for them; the JWKS fetch keeps the
// browser's context on purpose, being an idempotent read, and a browser context
// carries no deadline at all. This client's timeout is therefore the only thing
// standing between a peer that accepts the connection and never answers and a
// handler held open for as long as the browser waits (#338).
func TestNewAuthServerHTTPClient_CarriesTheConfiguredTimeout(t *testing.T) {
	client := newAuthServerHTTPClient()

	require.NotNil(t, client)
	assert.Equal(t, oauthclient.TokenExchangeTimeout, client.Timeout,
		"the one client this process uses against the auth server is bounded")
}
