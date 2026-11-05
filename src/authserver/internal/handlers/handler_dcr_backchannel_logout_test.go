package handlers

// A registration's backchannel_logout_uri and backchannel_logout_session_required, through
// POST /connect/register (#784 decision 10).
//
// The URI follows OpenID Connect Back-Channel Logout 1.0 section 2.2 as decision 6 settles it for a
// self-registered client: https only, whatever the client type. A URI that breaks the rule, a URI on
// a registration with no flow that signs users in, and a session-required value that is not a
// boolean are refused with RFC 7591 section 3.2.2's invalid_client_metadata, naming the field. A
// stored URI is echoed with the flag (section 3.2.1); the flag sent without a URI is stored false,
// since section 2.2 ties it to the URI being used.
//
// The bodies are raw JSON, so a value of the wrong type can be sent, and the answers are read as
// raw JSON, so a field the answer leaves out is told apart from one it carries as false.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// serveDCRBody posts a raw registration body to the handler.
func serveDCRBody(t *testing.T, body string, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/connect/register", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{Id: 1, DynamicClientRegistrationEnabled: true}))

	rr := httptest.NewRecorder()
	HandleDynamicClientRegistrationPost(database, auditLogger, testDataCipher).ServeHTTP(rr, req)
	return rr
}

// registerBackchannelBody serves a raw registration the database accepts, and returns the client it
// was handed to write and the answer's members as raw JSON.
func registerBackchannelBody(t *testing.T, body string) (*record.Client, map[string]json.RawMessage) {
	t.Helper()
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	var written *record.Client
	datamocks.ExpectRunInTransaction(database, dcrTx)
	database.On("CreateClient", mock.Anything, dcrTx, mock.Anything).
		Run(func(args mock.Arguments) { written = args.Get(2).(*record.Client) }).Return(nil).Once()
	database.On("CreateRedirectURI", mock.Anything, dcrTx, mock.Anything).Return(nil).Maybe()
	auditLogger.On("Log", mock.Anything, audit.EventDynamicClientRegistration, mock.Anything).Return().Once()

	rr := serveDCRBody(t, body, database, auditLogger)
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	require.NotNil(t, written)

	var members map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &members))
	return written, members
}

// confidentialBody and publicBody are registrations of each client type with one redirect URI the
// type accepts, and the given members added.
func confidentialBody(members string) string {
	return `{"redirect_uris":["https://client.example.com/callback"]` + members + `}`
}

func publicBody(members string) string {
	return `{"redirect_uris":["http://127.0.0.1:8765/callback"],"token_endpoint_auth_method":"none"` + members + `}`
}

func backchannelURIOfBytes(t *testing.T, n int) string {
	t.Helper()
	uri := "https://app.example.com/backchannel-logout/"
	uri += strings.Repeat("a", n-len(uri))
	require.Len(t, uri, n)
	return uri
}

// An accepted URI is stored exactly as sent, with the flag, and both are echoed. The flag is echoed
// as false too: a stored URI always comes back with it.
func TestHandleDynamicClientRegistrationPost_StoresAndEchoesABackchannelLogoutURI(t *testing.T) {
	long := backchannelURIOfBytes(t, 2048)
	tests := []struct {
		name            string
		body            string
		uri             string
		sessionRequired bool
		echoedFlag      string
	}{
		{name: "confidential, https, session required",
			body: confidentialBody(`,"backchannel_logout_uri":"https://app.example.com/backchannel-logout","backchannel_logout_session_required":true`),
			uri:  "https://app.example.com/backchannel-logout", sessionRequired: true, echoedFlag: "true"},
		{name: "confidential, https, flag left out",
			body: confidentialBody(`,"backchannel_logout_uri":"https://app.example.com/backchannel-logout"`),
			uri:  "https://app.example.com/backchannel-logout", echoedFlag: "false"},
		{name: "public, https, flag false",
			body: publicBody(`,"backchannel_logout_uri":"https://app.example.com/backchannel-logout","backchannel_logout_session_required":false`),
			uri:  "https://app.example.com/backchannel-logout", echoedFlag: "false"},
		{name: "a query, kept exactly",
			body: confidentialBody(`,"backchannel_logout_uri":"https://App.example.com:8443/bc?tenant=a&x=%2F"`),
			uri:  "https://App.example.com:8443/bc?tenant=a&x=%2F", echoedFlag: "false"},
		{name: "2048 bytes",
			body: confidentialBody(`,"backchannel_logout_uri":"` + long + `"`),
			uri:  long, echoedFlag: "false"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			written, members := registerBackchannelBody(t, tc.body)

			assert.Equal(t, tc.uri, written.BackchannelLogoutURI)
			assert.Equal(t, tc.sessionRequired, written.BackchannelLogoutSessionRequired)

			var echoedURI string
			require.Contains(t, members, "backchannel_logout_uri")
			require.NoError(t, json.Unmarshal(members["backchannel_logout_uri"], &echoedURI))
			assert.Equal(t, tc.uri, echoedURI)
			require.Contains(t, members, "backchannel_logout_session_required", "a stored URI is echoed with its flag")
			assert.Equal(t, tc.echoedFlag, string(members["backchannel_logout_session_required"]))
		})
	}
}

// With no URI stored, the flag is stored false whatever was sent, and the answer carries neither
// field.
func TestHandleDynamicClientRegistrationPost_NoBackchannelLogoutURIStoresNeitherSetting(t *testing.T) {
	tests := map[string]string{
		"both left out":                  confidentialBody(``),
		"an empty URI":                   confidentialBody(`,"backchannel_logout_uri":""`),
		"the flag alone":                 confidentialBody(`,"backchannel_logout_session_required":true`),
		"the flag with an empty URI":     confidentialBody(`,"backchannel_logout_uri":"","backchannel_logout_session_required":true`),
		"the flag alone, client creds":   `{"grant_types":["client_credentials"],"backchannel_logout_session_required":true}`,
		"an empty URI, no sign-in flow":  `{"grant_types":["client_credentials"],"backchannel_logout_uri":""}`,
		"the flag alone, public client":  publicBody(`,"backchannel_logout_session_required":true`),
		"the flag false, nothing else":   confidentialBody(`,"backchannel_logout_session_required":false`),
		"the flag alone on a code grant": `{"redirect_uris":["https://client.example.com/callback"],"grant_types":["authorization_code","refresh_token"],"backchannel_logout_session_required":true}`,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			written, members := registerBackchannelBody(t, body)

			assert.Empty(t, written.BackchannelLogoutURI)
			assert.False(t, written.BackchannelLogoutSessionRequired, "the flag is tied to the URI being used")
			assert.NotContains(t, members, "backchannel_logout_uri")
			assert.NotContains(t, members, "backchannel_logout_session_required")
		})
	}
}

// Each refusal of decision 10 is invalid_client_metadata naming the field and why, and reaches no
// write. A self-registered client gets https only, whatever its type, and no loopback exception.
func TestHandleDynamicClientRegistrationPost_RefusesABackchannelLogoutSettingItCannotUse(t *testing.T) {
	tests := []struct {
		name string
		body string
		// field is the member the description must name.
		field string
		// says is a further fragment the description must carry.
		says string
		// hidden is a fragment the description must not repeat.
		hidden string
	}{
		{name: "confidential, http",
			body:  confidentialBody(`,"backchannel_logout_uri":"http://app.example.com/backchannel-logout"`),
			field: "backchannel_logout_uri", says: "https"},
		{name: "public, http",
			body:  publicBody(`,"backchannel_logout_uri":"http://app.example.com/backchannel-logout"`),
			field: "backchannel_logout_uri", says: "https"},
		{name: "loopback http",
			body:  confidentialBody(`,"backchannel_logout_uri":"http://127.0.0.1:3000/backchannel-logout"`),
			field: "backchannel_logout_uri", says: "https"},
		{name: "another scheme",
			body:  confidentialBody(`,"backchannel_logout_uri":"ftp://app.example.com/backchannel-logout"`),
			field: "backchannel_logout_uri", says: "https"},
		{name: "a relative reference",
			body:  confidentialBody(`,"backchannel_logout_uri":"/backchannel-logout"`),
			field: "backchannel_logout_uri", says: "absolute"},
		{name: "no host",
			body:  confidentialBody(`,"backchannel_logout_uri":"https:///backchannel-logout"`),
			field: "backchannel_logout_uri", says: "absolute"},
		{name: "a fragment",
			body:  confidentialBody(`,"backchannel_logout_uri":"https://app.example.com/backchannel-logout#top"`),
			field: "backchannel_logout_uri", says: "fragment"},
		{name: "an excluded character",
			body:  confidentialBody(`,"backchannel_logout_uri":"https://app.example.com/<svg>"`),
			field: "backchannel_logout_uri", says: "absolute"},
		{name: "a malformed escape",
			body:  confidentialBody(`,"backchannel_logout_uri":"https://app.example.com/bc?x=%zz"`),
			field: "backchannel_logout_uri", says: "absolute"},
		{name: "userinfo, not repeated",
			body:  confidentialBody(`,"backchannel_logout_uri":"https://alice:s3cret@app.example.com/backchannel-logout"`),
			field: "backchannel_logout_uri", says: "user name or password", hidden: "s3cret"},
		{name: "2049 bytes",
			body:  confidentialBody(`,"backchannel_logout_uri":"` + backchannelURIOfBytes(t, 2049) + `"`),
			field: "backchannel_logout_uri", says: "2048 bytes"},
		{name: "no flow that signs users in",
			body:  `{"grant_types":["client_credentials"],"backchannel_logout_uri":"https://app.example.com/backchannel-logout"}`,
			field: "backchannel_logout_uri", says: "authorization_code"},
		{name: "a URI that is not a string",
			body:  confidentialBody(`,"backchannel_logout_uri":["https://app.example.com/backchannel-logout"]`),
			field: "backchannel_logout_uri", says: "string"},
		{name: "the flag as a string",
			body:  confidentialBody(`,"backchannel_logout_uri":"https://app.example.com/backchannel-logout","backchannel_logout_session_required":"true"`),
			field: "backchannel_logout_session_required", says: "boolean"},
		{name: "the flag as a number",
			body:  confidentialBody(`,"backchannel_logout_session_required":1`),
			field: "backchannel_logout_session_required", says: "boolean"},
		{name: "the flag as an object, with no URI",
			body:  confidentialBody(`,"backchannel_logout_session_required":{}`),
			field: "backchannel_logout_session_required", says: "boolean"},
		{name: "the flag as null",
			body:  confidentialBody(`,"backchannel_logout_uri":"https://app.example.com/backchannel-logout","backchannel_logout_session_required":null`),
			field: "backchannel_logout_session_required", says: "boolean"},
		{name: "the flag as null, with no URI",
			body:  confidentialBody(`,"backchannel_logout_session_required":null`),
			field: "backchannel_logout_session_required", says: "boolean"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			rr := serveDCRBody(t, tc.body, database, auditLogger)

			require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
			envelope := decodeDCRError(t, rr)
			assert.Equal(t, "invalid_client_metadata", envelope.Error)
			assert.Contains(t, envelope.ErrorDescription, tc.field)
			assert.Contains(t, envelope.ErrorDescription, tc.says)
			if tc.hidden != "" {
				assert.NotContains(t, envelope.ErrorDescription, tc.hidden)
			}
			database.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
		})
	}
}

// A refused value of another field keeps the answer it had: only the two back-channel members are
// named when their type is wrong.
func TestHandleDynamicClientRegistrationPost_AnotherFieldOfTheWrongTypeIsStillAnUnreadableBody(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	rr := serveDCRBody(t, `{"redirect_uris":"https://client.example.com/callback"}`, database, auditLogger)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	envelope := decodeDCRError(t, rr)
	assert.Equal(t, "invalid_client_metadata", envelope.Error)
	assert.Equal(t, "Invalid request body", envelope.ErrorDescription)
}
