package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// RFC 8414 section 3 lets a server publish its metadata at more than one well-known address, and
// section 3.2 lets the document carry fields beyond RFC 8414's own, so the OIDC discovery document
// is served unchanged at /.well-known/oauth-authorization-server too: one document, which the two
// addresses cannot disagree about, readable from any origin as the OIDC address is, since the
// clients this address exists for include MCP clients running in a browser (#576, decision 1).
// Driven through the real initMiddleware and initRoutes, because the route and the CORS mount are
// what this owns; the document itself is the handler's table test.

const (
	oidcDiscoveryPath    = "/.well-known/openid-configuration"
	rfc8414DiscoveryPath = "/.well-known/oauth-authorization-server"
)

func newDiscoveryTestServer(t *testing.T) *Server {
	t.Helper()
	database := datamocks.NewDatabase(t)
	database.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).
		Return(&record.Settings{Id: 1, Issuer: "https://issuer.example"}, nil)
	return newFaultsTestServer(database)
}

func serveDiscoveryRoute(s *Server, method, path, origin string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, req)
	return rr
}

func TestInitRoutes_TheRFC8414AddressServesTheOIDCDiscoveryDocument(t *testing.T) {
	s := newDiscoveryTestServer(t)

	oidc := serveDiscoveryRoute(s, http.MethodGet, oidcDiscoveryPath, "")
	rfc8414 := serveDiscoveryRoute(s, http.MethodGet, rfc8414DiscoveryPath, "")

	require.Equal(t, http.StatusOK, oidc.Code, oidc.Body.String())
	require.Equal(t, http.StatusOK, rfc8414.Code, rfc8414.Body.String())
	assert.Equal(t, "application/json", rfc8414.Header().Get("Content-Type"))

	// The issuer read from the settings, so the comparison below is of two documents and not of two
	// identical refusals.
	var document map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rfc8414.Body.Bytes(), &document), rfc8414.Body.String())
	assert.JSONEq(t, `"https://issuer.example"`, string(document["issuer"]))

	assert.Equal(t, oidc.Body.String(), rfc8414.Body.String(), "the two addresses serve one document")
}

func TestInitRoutes_TheRFC8414AddressAnswersHEAD(t *testing.T) {
	s := newDiscoveryTestServer(t)

	get := serveDiscoveryRoute(s, http.MethodGet, rfc8414DiscoveryPath, "")
	head := serveDiscoveryRoute(s, http.MethodHead, rfc8414DiscoveryPath, "")

	assert.Equal(t, http.StatusOK, head.Code)
	assert.Equal(t, get.Header().Get("Content-Type"), head.Header().Get("Content-Type"))
	// The content a HEAD must not carry is net/http's to discard, which a recorder does not do; the
	// integration tier's HEAD sweep reads it off the wire.
}

func TestInitRoutes_TheRFC8414AddressIsReadableFromAnyOrigin(t *testing.T) {
	s := newDiscoveryTestServer(t)

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			rr := serveDiscoveryRoute(s, method, rfc8414DiscoveryPath, "https://mcp-client.example")

			assert.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, "https://mcp-client.example", rr.Result().Header.Get("Access-Control-Allow-Origin"))
		})
	}
}

// RFC 8414 section 3.1's path-suffixed address is the reverse proxy's to route to the one above; no
// route of the server answers it.
func TestInitRoutes_NoRouteAnswersThePathSuffixedRFC8414Address(t *testing.T) {
	s := newDiscoveryTestServer(t)

	rr := serveDiscoveryRoute(s, http.MethodGet, rfc8414DiscoveryPath+"/tenant", "")

	assert.Equal(t, http.StatusNotFound, rr.Code)
}
