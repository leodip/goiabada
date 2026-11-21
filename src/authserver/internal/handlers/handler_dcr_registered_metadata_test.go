package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// serveRawRegistration serves a registration sent as raw JSON, so a member the request type does not read,
// such as response_types, reaches the handler, and returns the answer with the audit entry's
// details.
func serveRawRegistration(t *testing.T, body string) (*httptest.ResponseRecorder, map[string]interface{}) {
	t.Helper()
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	var details map[string]interface{}
	datamocks.ExpectRunInTransaction(database, dcrTx)
	database.On("CreateClient", mock.Anything, dcrTx, mock.Anything).Return(nil).Once()
	database.On("CreateRedirectURI", mock.Anything, dcrTx, mock.Anything).Return(nil).Maybe()
	auditLogger.On("Log", mock.Anything, audit.EventDynamicClientRegistration, mock.Anything).
		Run(func(args mock.Arguments) { details = args.Get(2).(map[string]interface{}) }).Return().Once()

	req := httptest.NewRequest(http.MethodPost, "/connect/register", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{ID: 1, DynamicClientRegistrationEnabled: true}))
	rr := httptest.NewRecorder()
	HandleDynamicClientRegistrationPost(database, auditLogger, testDataCipher).ServeHTTP(rr, req)

	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	require.NotNil(t, details)
	return rr, details
}

// The answer's grant_types and response_types describe the client that was stored, not the
// request (RFC 7591 section 3.2.1, #708 decisions 4 and 6): a client with the authorization code
// flow is told authorization_code with refresh_token, since every code it redeems comes with a
// refresh token, and response type code; one with the client credentials grant alone is told
// client_credentials, which issues no refresh token, and no response type. The order is the
// discovery document's. The audit entry records the same grant list. Every expected list is a
// literal.
func TestHandleDynamicClientRegistrationPost_AnswersTheGrantAndResponseTypesOfTheStoredClient(t *testing.T) {
	tests := []struct {
		name              string
		body              string
		wantGrantTypes    []string
		wantResponseTypes string
	}{
		{
			name:              "a default registration",
			body:              `{"redirect_uris":["https://client.example.com/cb"]}`,
			wantGrantTypes:    []string{"authorization_code", "refresh_token"},
			wantResponseTypes: `["code"]`,
		},
		{
			name:              "a public default registration",
			body:              `{"redirect_uris":["http://127.0.0.1:8765/cb"],"token_endpoint_auth_method":"none"}`,
			wantGrantTypes:    []string{"authorization_code", "refresh_token"},
			wantResponseTypes: `["code"]`,
		},
		{
			name:              "authorization_code and refresh_token",
			body:              `{"redirect_uris":["https://client.example.com/cb"],"grant_types":["authorization_code","refresh_token"]}`,
			wantGrantTypes:    []string{"authorization_code", "refresh_token"},
			wantResponseTypes: `["code"]`,
		},
		{
			name:              "client_credentials alone",
			body:              `{"grant_types":["client_credentials"]}`,
			wantGrantTypes:    []string{"client_credentials"},
			wantResponseTypes: `[]`,
		},
		{
			name:              "client_credentials and refresh_token",
			body:              `{"grant_types":["client_credentials","refresh_token"]}`,
			wantGrantTypes:    []string{"client_credentials"},
			wantResponseTypes: `[]`,
		},
		{
			name:              "client_credentials before authorization_code",
			body:              `{"redirect_uris":["https://client.example.com/cb"],"grant_types":["client_credentials","authorization_code"]}`,
			wantGrantTypes:    []string{"authorization_code", "refresh_token", "client_credentials"},
			wantResponseTypes: `["code"]`,
		},
		{
			// The request's response_types is accepted and not stored; the answer carries the
			// replacement (OpenID Connect Dynamic Client Registration 1.0 section 3.2).
			name:              "a response type the client cannot use",
			body:              `{"redirect_uris":["https://client.example.com/cb"],"response_types":["token"]}`,
			wantGrantTypes:    []string{"authorization_code", "refresh_token"},
			wantResponseTypes: `["code"]`,
		},
		{
			name:              "a response type on a client credentials registration",
			body:              `{"grant_types":["client_credentials"],"response_types":["code"]}`,
			wantGrantTypes:    []string{"client_credentials"},
			wantResponseTypes: `[]`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr, details := serveRawRegistration(t, tc.body)

			var raw map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &raw))
			require.Contains(t, raw, "response_types", "response_types is always present")
			assert.JSONEq(t, tc.wantResponseTypes, string(raw["response_types"]))

			response := decodeDCRResponse(t, rr)
			assert.Equal(t, tc.wantGrantTypes, response.GrantTypes)
			assert.Equal(t, tc.wantGrantTypes, details["grant_types"], "the audit entry records the answer's list")
		})
	}
}

// A registration that would enable no flow, refresh_token alone, is refused invalid_client_metadata
// and creates nothing (RFC 7591 section 2.1, #708 decision 4): such a client could never get a
// token. The strict database mock has no expectation, so reaching the transaction fails the case.
func TestHandleDynamicClientRegistrationPost_RefusesARegistrationThatEnablesNoFlow(t *testing.T) {
	for _, grantTypes := range [][]string{
		{"refresh_token"},
		{"refresh_token", "refresh_token"},
	} {
		t.Run(grantTypes[0], func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			rr := serveDCR(t, oidc.DynamicClientRegistrationRequest{
				RedirectURIs: []string{"https://client.example.com/cb"},
				GrantTypes:   grantTypes,
			}, database, auditLogger)

			assert.Equal(t, http.StatusBadRequest, rr.Code)
			envelope := decodeDCRError(t, rr)
			assert.Equal(t, "invalid_client_metadata", envelope.Error)
			assert.Equal(t,
				"grant_types enables no flow: refresh_token alone cannot get a token. Include authorization_code or client_credentials",
				envelope.ErrorDescription)
			database.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// A confidential registration stores the token_endpoint_auth_method it registered, the default
// client_secret_basic when it named none, and a public one stores the empty string, the value of a
// client not held to one method (#708 decision 3). The audit entry records the answer's method,
// none for a public client (#708 decision 7). Every expected value is a literal.
func TestHandleDynamicClientRegistrationPost_StoresTheRegisteredMethod(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantStored  string
		wantAudited string
	}{
		{
			name:        "no method named",
			body:        `{"redirect_uris":["https://client.example.com/cb"]}`,
			wantStored:  "client_secret_basic",
			wantAudited: "client_secret_basic",
		},
		{
			name:        "client_secret_basic",
			body:        `{"redirect_uris":["https://client.example.com/cb"],"token_endpoint_auth_method":"client_secret_basic"}`,
			wantStored:  "client_secret_basic",
			wantAudited: "client_secret_basic",
		},
		{
			name:        "client_secret_post",
			body:        `{"redirect_uris":["https://client.example.com/cb"],"token_endpoint_auth_method":"client_secret_post"}`,
			wantStored:  "client_secret_post",
			wantAudited: "client_secret_post",
		},
		{
			name:        "client_secret_post with client_credentials",
			body:        `{"grant_types":["client_credentials"],"token_endpoint_auth_method":"client_secret_post"}`,
			wantStored:  "client_secret_post",
			wantAudited: "client_secret_post",
		},
		{
			name:        "none",
			body:        `{"redirect_uris":["http://127.0.0.1:8765/cb"],"token_endpoint_auth_method":"none"}`,
			wantStored:  "",
			wantAudited: "none",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			var stored *record.Client
			var details map[string]interface{}
			datamocks.ExpectRunInTransaction(database, dcrTx)
			database.On("CreateClient", mock.Anything, dcrTx, mock.Anything).
				Run(func(args mock.Arguments) { stored = args.Get(2).(*record.Client) }).Return(nil).Once()
			database.On("CreateRedirectURI", mock.Anything, dcrTx, mock.Anything).Return(nil).Maybe()
			auditLogger.On("Log", mock.Anything, audit.EventDynamicClientRegistration, mock.Anything).
				Run(func(args mock.Arguments) { details = args.Get(2).(map[string]interface{}) }).Return().Once()

			req := httptest.NewRequest(http.MethodPost, "/connect/register", bytes.NewReader([]byte(tc.body)))
			req.Header.Set("Content-Type", "application/json")
			req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{ID: 1, DynamicClientRegistrationEnabled: true}))
			rr := httptest.NewRecorder()
			HandleDynamicClientRegistrationPost(database, auditLogger, testDataCipher).ServeHTTP(rr, req)

			require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
			require.NotNil(t, stored)
			assert.Equal(t, tc.wantStored, stored.TokenEndpointAuthMethod, "the record passed to the client insert")
			assert.Equal(t, tc.wantAudited, details["token_endpoint_auth_method"], "the audit entry records the answer's method")
			assert.Equal(t, tc.wantAudited, decodeDCRResponse(t, rr).TokenEndpointAuthMethod)
		})
	}
}
