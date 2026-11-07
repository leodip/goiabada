package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// What the protocol endpoints tell caches (#714). Discovery and the key set are public and change
// only on a key rotation, which publishes the next key before it signs, so each may be kept five
// minutes. /userinfo answers a user's claims and is stored by no cache, success and refusal alike.
// Driven through the real initMiddleware and initRoutes, since what reaches the client is the
// router's to decide as much as the handler's.

const certsPath = "/certs"

// testJWK is a signing key's public JWK as the key_pairs row stores it: RFC 7517 appendix A.1's
// RSA key, under a kid of this file's choosing.
const testJWK = `{"kty":"RSA","kid":"test-key","use":"sig","alg":"RS256","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}`

func newCertsTestServer(t *testing.T, keys []record.KeyPair, err error) *Server {
	t.Helper()
	database := datamocks.NewDatabase(t)
	database.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).
		Return(&record.Settings{Id: 1, Issuer: "https://issuer.example"}, nil).Maybe()
	database.On("GetAllSigningKeys", mock.Anything, mock.Anything).Return(keys, err)
	return newFaultsTestServer(database)
}

func currentSigningKey() record.KeyPair {
	return record.KeyPair{Id: 1, State: record.KeyStateCurrent.String(), KeyIdentifier: "test-key",
		Type: "RSA", Algorithm: "RS256", PublicKeyJWK: []byte(testJWK)}
}

// RFC 9111 section 5.2.2.1 gives a response a freshness lifetime with max-age, and public lets a
// shared cache keep it: both discovery addresses and the key set, by GET and by HEAD.
func TestInitRoutes_DiscoveryAndTheKeySetMayBeCachedForFiveMinutes(t *testing.T) {
	s := newCertsTestServer(t, []record.KeyPair{currentSigningKey()}, nil)

	for _, path := range []string{oidcDiscoveryPath, rfc8414DiscoveryPath, certsPath} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			t.Run(method+" "+path, func(t *testing.T) {
				rr := serveDiscoveryRoute(s, method, path, "")
				result := rr.Result()
				defer func() { _ = result.Body.Close() }()

				require.Equal(t, http.StatusOK, result.StatusCode, rr.Body.String())
				assert.Equal(t, "public, max-age=300", result.Header.Get("Cache-Control"))
				assert.Empty(t, result.Header.Get("Pragma"), "a cacheable answer carries no Pragma: no-cache")
			})
		}
	}
}

// A key set the server could not read is a fault, not a key set: it is answered as every protocol
// endpoint's fault is, no-store, and never given five minutes in a shared cache.
func TestInitRoutes_AKeySetFaultIsNotCacheable(t *testing.T) {
	s := newCertsTestServer(t, nil, errors.New("the database is down"))

	rr := serveDiscoveryRoute(s, http.MethodGet, certsPath, "")
	result := rr.Result()
	defer func() { _ = result.Body.Close() }()

	assert.Equal(t, http.StatusInternalServerError, result.StatusCode)
	assert.Equal(t, "no-store", result.Header.Get("Cache-Control"))
	assert.Equal(t, "no-cache", result.Header.Get("Pragma"))
}

// RFC 7517 section 5: a JWK Set "MUST have a "keys" member, with its value being an array of
// JWKs". With no keys that array is empty, not null.
func TestInitRoutes_AnEmptyKeySetIsAnEmptyArray(t *testing.T) {
	for name, keys := range map[string][]record.KeyPair{"no rows": nil, "an empty list": {}} {
		t.Run(name, func(t *testing.T) {
			s := newCertsTestServer(t, keys, nil)

			rr := serveDiscoveryRoute(s, http.MethodGet, certsPath, "")

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			assert.JSONEq(t, `{"keys":[]}`, rr.Body.String())
		})
	}

	t.Run("one key is a list of one", func(t *testing.T) {
		s := newCertsTestServer(t, []record.KeyPair{currentSigningKey()}, nil)

		rr := serveDiscoveryRoute(s, http.MethodGet, certsPath, "")

		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		assert.JSONEq(t, `{"keys":[`+testJWK+`]}`, rr.Body.String())
	})
}

// Every /userinfo answer carries the pair RFC 6749 section 5.1 names, the bare 401 to a request
// with no token included: middleware.NoStore heads both chains, ahead of the bearer guards whose
// refusal writer commits its own status. The success, the 401 invalid_token and the 403 are the
// integration tier's, which holds real tokens.
func TestInitRoutes_UserinfoRefusesToBeStored(t *testing.T) {
	s := newRoutesTestServer(t)

	var userinfoRoutes []string
	err := s.router.Walk(func(method string, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		if route != "/userinfo" {
			return nil
		}
		userinfoRoutes = append(userinfoRoutes, method)
		var first string
		if len(middlewares) > 0 {
			first = runtime.FuncForPC(reflect.ValueOf(middlewares[0]).Pointer()).Name()
		}
		assert.True(t, strings.HasPrefix(first, noStoreMiddlewareName+"."),
			"middleware.NoStore must be the FIRST middleware on %s /userinfo; the chain starts with %q", method, first)
		return nil
	})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{http.MethodGet, http.MethodPost}, userinfoRoutes,
		"both /userinfo registrations are checked")

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method+" with no token", func(t *testing.T) {
			recorder := serve(s, withRoutesTestSettings(httptest.NewRequest(method, "/userinfo", nil)))
			result := recorder.Result()
			defer func() { _ = result.Body.Close() }()

			assert.Equal(t, http.StatusUnauthorized, result.StatusCode)
			assert.Equal(t, `Bearer realm="goiabada"`, result.Header.Get("WWW-Authenticate"))
			assert.Equal(t, "no-store", result.Header.Get("Cache-Control"))
			assert.Equal(t, "no-cache", result.Header.Get("Pragma"))
		})
	}
}
