package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/clientauth"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/introspectionmetrics"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/render"
	"github.com/leodip/goiabada/authserver/internal/revocationmetrics"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/metrics"
)

// The client authentication limit at the revocation and introspection endpoints (#707 decisions 2,
// 6, 7 and 10), over HTTP with the real writer, the limiter port faked beneath it: a client over its
// budget is answered the 429 the token endpoint answers, counted in neither endpoint's own metric,
// and a count that cannot be read is each endpoint's own fault.

// limitedEndpoint is the revocation or the introspection endpoint over a mocked database and token
// parser, its secret checks bounded by limiter, counting in its own registry.
type limitedEndpoint struct {
	name        string
	path        string
	warning     string
	faultStatus int
	faultCode   string
	family      string
	handler     func(t *testing.T, database *datamocks.Database, limiter clientauth.SecretCheckLimiter, registry *metrics.Registry) http.HandlerFunc
}

func limitedEndpoints() []limitedEndpoint {
	return []limitedEndpoint{
		{
			name: "revocation", path: "/auth/revoke", warning: "client authentication refused at the revocation endpoint",
			faultStatus: http.StatusServiceUnavailable, faultCode: "temporarily_unavailable",
			family: "goiabada_revocation_requests_total",
			handler: func(t *testing.T, database *datamocks.Database, limiter clientauth.SecretCheckLimiter, registry *metrics.Registry) http.HandlerFunc {
				return HandleRevokePost(render.New(nil, nil), database, handlersmocks.NewTokenParser(t), testDataCipher, limiter,
					handlersmocks.NewAuditLogger(t), revocationmetrics.Register(registry))
			},
		},
		{
			name: "introspection", path: "/auth/introspect", warning: "client authentication refused at the introspection endpoint",
			faultStatus: http.StatusInternalServerError, faultCode: "server_error",
			family: "goiabada_introspection_requests_total",
			handler: func(t *testing.T, database *datamocks.Database, limiter clientauth.SecretCheckLimiter, registry *metrics.Registry) http.HandlerFunc {
				return HandleIntrospectPost(render.New(nil, nil), database, handlersmocks.NewTokenParser(t), testDataCipher, limiter,
					introspectionmetrics.Register(registry))
			},
		},
	}
}

// serve posts a request for the token "the.presented.token" by the_client with secret, in the
// Authorization header when basic is set and in the body otherwise.
func (e limitedEndpoint) serve(t *testing.T, limiter clientauth.SecretCheckLimiter, client *record.Client, secret string,
	basic bool, registry *metrics.Registry) *httptest.ResponseRecorder {

	t.Helper()
	database := datamocks.NewDatabase(t)
	database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, client.ClientIdentifier).Return(client, nil).Once()
	form := url.Values{"token": {"the.presented.token"}}
	if !basic {
		form.Set("client_id", client.ClientIdentifier)
		form.Set("client_secret", secret)
	}
	req := httptest.NewRequest(http.MethodPost, e.path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic {
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(client.ClientIdentifier+":"+secret)))
	}
	req = withSettings(req, &record.Settings{Id: 1, Issuer: "https://auth.example.com"})
	rr := httptest.NewRecorder()
	e.handler(t, database, limiter, registry).ServeHTTP(rr, req)
	return rr
}

// samples answers the endpoint's own metric's sample lines.
func (e limitedEndpoint) samples(t *testing.T, registry *metrics.Registry) []string {
	t.Helper()
	rec := httptest.NewRecorder()
	registry.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var samples []string
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if strings.HasPrefix(line, e.family+"{") {
			samples = append(samples, line)
		}
	}
	return samples
}

func TestRevocationAndIntrospection_AClientOverItsLimitIsAnswered429(t *testing.T) {
	for _, endpoint := range limitedEndpoints() {
		for _, secret := range []string{"the_client_secret", "not_the_secret"} {
			for _, basic := range []bool{false, true} {
				t.Run(endpoint.name+" with "+secret+map[bool]string{false: " in the body", true: " in the header"}[basic], func(t *testing.T) {
					logs := logtest.CaptureSlog(t)
					registry := metrics.NewRegistry()
					limiter := &refusingSecretCheckLimiter{}

					rr := endpoint.serve(t, limiter, overLimitClient(t), secret, basic, registry)

					assert.Equal(t, http.StatusTooManyRequests, rr.Code)
					assert.Equal(t, "3600", rr.Header().Get("Retry-After"))
					assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
					assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))
					assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
					assert.Empty(t, rr.Header().Get("WWW-Authenticate"), "the credentials were never judged")
					var body map[string]string
					require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body), "the body must be JSON: %q", rr.Body.String())
					assert.Equal(t, map[string]string{
						"error":             "invalid_request",
						"error_description": "Too many requests. Please wait and try again later.",
					}, body)
					assert.Equal(t, []string{"the_client"}, limiter.asked)

					assert.Empty(t, endpoint.samples(t, registry), "a 429 is the rate limiter's refusal, counted under its limiter")
					for _, record := range logs.Records() {
						assert.NotEqual(t, endpoint.warning, record.Message, "the client was not refused authentication")
					}
				})
			}
		}
	}
}

// A count the limiter cannot read is each endpoint's own fault, with none of a refusal's headers:
// 503 temporarily_unavailable at revocation, 500 server_error at introspection, counted as error.
func TestRevocationAndIntrospection_AClientAuthenticationCountThatCannotBeReadIsAFault(t *testing.T) {
	for _, endpoint := range limitedEndpoints() {
		t.Run(endpoint.name, func(t *testing.T) {
			logtest.CaptureSlog(t)
			registry := metrics.NewRegistry()
			limiter := &refusingSecretCheckLimiter{fault: errors.New("connection refused")}

			rr := endpoint.serve(t, limiter, overLimitClient(t), "the_client_secret", false, registry)

			assert.Equal(t, endpoint.faultStatus, rr.Code)
			assert.Empty(t, rr.Header().Get("Retry-After"))
			assert.Empty(t, rr.Header().Get("WWW-Authenticate"))
			var body map[string]string
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body), rr.Body.String())
			assert.Equal(t, endpoint.faultCode, body["error"])
			assert.Equal(t, []string{"the_client"}, limiter.asked)
			assert.Equal(t, []string{endpoint.family + `{outcome="error"} 1`}, endpoint.samples(t, registry))
		})
	}
}

// A public client compares no secret, so neither endpoint asks the limiter for it: revocation
// authenticates it by its identifier and introspection refuses it as invalid_client, as without a
// limit.
func TestRevocationAndIntrospection_APublicClientSpendsNothing(t *testing.T) {
	public := &record.Client{Id: 84, ClientIdentifier: "the-spa", Enabled: true, IsPublic: true}
	for _, endpoint := range limitedEndpoints() {
		t.Run(endpoint.name, func(t *testing.T) {
			logtest.CaptureSlog(t)
			limiter := &refusingSecretCheckLimiter{}
			database := datamocks.NewDatabase(t)
			database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "the-spa").Return(public, nil).Once()
			// No token, so a client that authenticates is refused for the missing token, before it is read.
			req := httptest.NewRequest(http.MethodPost, endpoint.path, strings.NewReader(url.Values{"client_id": {"the-spa"}}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req = withSettings(req, &record.Settings{Id: 1})
			rr := httptest.NewRecorder()
			endpoint.handler(t, database, limiter, metrics.NewRegistry()).ServeHTTP(rr, req)

			assert.NotEqual(t, http.StatusTooManyRequests, rr.Code, rr.Body.String())
			assert.Empty(t, limiter.asked)
		})
	}
}
