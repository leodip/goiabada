package handlers

// A registration's post_logout_redirect_uris, through POST /connect/register (#147 decision 7).
//
// Each entry gets every check a registered redirect URI gets, under its own client type's table,
// and a refusal is invalid_client_metadata naming post_logout_redirect_uris and the value, since
// OpenID Connect Dynamic Client Registration 1.0 section 3.3 keeps invalid_redirect_uri for
// redirect_uris. The accepted list is written on the registration's transaction and echoed in the
// answer, which section 3.2 makes "all registered Metadata about this Client".

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// signOutRegistration is a registration of the given client type holding the given sign-out
// redirect URIs beside one redirect URI the type accepts.
func signOutRegistration(public bool, signOutURIs ...string) oidc.DynamicClientRegistrationRequest {
	if public {
		return oidc.DynamicClientRegistrationRequest{
			RedirectURIs:            []string{"http://127.0.0.1:8765/callback"},
			PostLogoutRedirectURIs:  signOutURIs,
			TokenEndpointAuthMethod: "none",
		}
	}
	return oidc.DynamicClientRegistrationRequest{
		RedirectURIs:           []string{"https://client.example.com/callback"},
		PostLogoutRedirectURIs: signOutURIs,
	}
}

// acceptRegistration stubs every write an accepted registration makes, recording the sign-out
// redirect URI rows it is handed.
func acceptRegistration(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) *[]record.PostLogoutRedirectURI {
	var written []record.PostLogoutRedirectURI
	datamocks.ExpectRunInTransaction(database, dcrTx)
	database.On("CreateClient", mock.Anything, dcrTx, mock.Anything).
		Run(func(args mock.Arguments) { args.Get(2).(*record.Client).Id = 42 }).Return(nil).Once()
	database.On("CreateRedirectURI", mock.Anything, dcrTx, mock.Anything).Return(nil).Maybe()
	database.On("CreatePostLogoutRedirectURI", mock.Anything, dcrTx, mock.Anything).
		Run(func(args mock.Arguments) {
			written = append(written, *args.Get(2).(*record.PostLogoutRedirectURI))
		}).Return(nil).Maybe()
	auditLogger.On("Log", mock.Anything, audit.EventDynamicClientRegistration, mock.Anything).Return().Once()
	return &written
}

func signOutURIsOfBytes(t *testing.T, n int) string {
	t.Helper()
	uri := "https://client.example.com/signed-out/"
	uri += strings.Repeat("a", n-len(uri))
	require.Len(t, uri, n)
	return uri
}

func numberedSignOutURIs(n int) []string {
	uris := make([]string, n)
	for i := range uris {
		uris[i] = fmt.Sprintf("https://client.example.com/signed-out/%d", i)
	}
	return uris
}

// Each rule of decision 7, for the client type it differs by. An accepted row is registered and
// echoed; a refused one is invalid_client_metadata naming the field, and reaches no write.
func TestHandleDynamicClientRegistrationPost_SignOutRedirectURIRules(t *testing.T) {
	tests := []struct {
		name     string
		public   bool
		uris     []string
		accepted bool
		// echoed is the value a refusal's description must repeat; empty for a bound, whose
		// description names the bound rather than an overlong value.
		echoed string
		// says is a further fragment the description must carry.
		says string
	}{
		// --- public: loopback http or a custom scheme, never https
		{name: "public, loopback http", public: true, uris: []string{"http://127.0.0.1:8765/signed-out"}, accepted: true},
		{name: "public, localhost http", public: true, uris: []string{"http://localhost:3000/signed-out"}, accepted: true},
		{name: "public, IPv6 loopback http", public: true, uris: []string{"http://[::1]:9000/signed-out"}, accepted: true},
		{name: "public, custom scheme", public: true, uris: []string{"com.example.app:/signed-out"}, accepted: true},
		{name: "public, https", public: true, uris: []string{"https://app.example.com/signed-out"},
			echoed: "https://app.example.com/signed-out", says: "public clients registered via DCR cannot use https post_logout_redirect_uris"},
		{name: "public, http off loopback", public: true, uris: []string{"http://app.example.com/signed-out"},
			echoed: "http://app.example.com/signed-out", says: "loopback hosts"},
		{name: "public, a host merely starting with localhost", public: true, uris: []string{"http://localhost.attacker.com/signed-out"},
			echoed: "http://localhost.attacker.com/signed-out", says: "loopback hosts"},

		// --- confidential: https or loopback http, never a custom scheme
		{name: "confidential, https", uris: []string{"https://app.example.com/signed-out"}, accepted: true},
		{name: "confidential, a query carrying state", uris: []string{"https://app.example.com/bye?state=fixed"}, accepted: true},
		{name: "confidential, loopback http", uris: []string{"http://127.0.0.1:3000/signed-out"}, accepted: true},
		{name: "confidential, custom scheme", uris: []string{"myapp://signed-out"},
			echoed: "myapp://signed-out", says: "confidential clients must use an https"},
		{name: "confidential, http off loopback", uris: []string{"http://app.example.com/signed-out"},
			echoed: "http://app.example.com/signed-out", says: "loopback hosts"},

		// --- either type: an absolute URI, no excluded character, no denied scheme
		{name: "a relative reference", uris: []string{"/signed-out"}, echoed: "/signed-out"},
		{name: "a fragment", uris: []string{"https://app.example.com/signed-out#top"},
			echoed: "https://app.example.com/signed-out#top", says: "must be an absolute URI"},
		{name: "https with no host", uris: []string{"https:///evil.example/signed-out"},
			echoed: "https:///evil.example/signed-out", says: "must be an absolute URI"},
		{name: "markup", uris: []string{"https://app.example.com/<svg/onload=alert(1)>"},
			echoed: "https://app.example.com/"},
		{name: "javascript", public: true, uris: []string{"javascript:alert(1)"},
			echoed: "javascript:alert(1)", says: "is not permitted"},
		{name: "ftp", public: true, uris: []string{"ftp://evil.example/signed-out"},
			echoed: "ftp://evil.example/signed-out", says: "is not permitted"},

		// --- bounds, counted apart from the redirect URIs
		{name: "60 entries", uris: numberedSignOutURIs(60), accepted: true},
		{name: "61 entries", uris: numberedSignOutURIs(61), says: "cannot hold more than 60 entries"},
		{name: "2048 bytes", uris: []string{signOutURIsOfBytes(t, 2048)}, accepted: true},
		{name: "2049 bytes", uris: []string{signOutURIsOfBytes(t, 2049)}, says: "cannot exceed 2048 bytes"},
		{name: "an entry listed twice", uris: []string{"https://app.example.com/a", "https://app.example.com/b", "https://app.example.com/a"},
			echoed: "https://app.example.com/a", says: "listed more than once"},
		{name: "two entries differing only in case", uris: []string{"https://app.example.com/A", "https://app.example.com/a"}, accepted: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			request := signOutRegistration(tc.public, tc.uris...)

			if tc.accepted {
				written := acceptRegistration(database, auditLogger)
				rr := serveDCR(t, request, database, auditLogger)
				require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
				assert.Equal(t, tc.uris, decodeDCRResponse(t, rr).PostLogoutRedirectURIs)
				stored := make([]string, 0, len(*written))
				for _, row := range *written {
					assert.Equal(t, int64(42), row.ClientId)
					stored = append(stored, row.URI)
				}
				assert.Equal(t, tc.uris, stored)
				return
			}

			rr := serveDCR(t, request, database, auditLogger)
			assert.Equal(t, http.StatusBadRequest, rr.Code)
			envelope := decodeDCRError(t, rr)
			assert.Equal(t, "invalid_client_metadata", envelope.Error)
			assert.Contains(t, envelope.ErrorDescription, "post_logout_redirect_uris")
			if tc.echoed != "" {
				assert.Contains(t, envelope.ErrorDescription, tc.echoed)
			}
			if tc.says != "" {
				assert.Contains(t, envelope.ErrorDescription, tc.says)
			}
			database.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
		})
	}
}

// The client, its redirect URIs and its sign-out redirect URIs are one write, and the audit event
// follows the commit.
func TestHandleDynamicClientRegistrationPost_WritesTheSignOutRedirectURIsInTheRegistrationsTransaction(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	var events []string
	note := func(event string) { events = append(events, event) }
	datamocks.ExpectRunInTransaction(database, dcrTx, note)
	database.On("CreateClient", mock.Anything, dcrTx, mock.Anything).
		Run(func(args mock.Arguments) {
			args.Get(2).(*record.Client).Id = 42
			note("client")
		}).Return(nil).Once()
	database.On("CreateRedirectURI", mock.Anything, dcrTx, mock.Anything).
		Run(func(mock.Arguments) { note("redirect uri") }).Return(nil).Once()
	for _, uri := range []string{"https://client.example.com/signed-out", "https://client.example.com/bye?state=fixed"} {
		database.On("CreatePostLogoutRedirectURI", mock.Anything, dcrTx, mock.MatchedBy(func(r *record.PostLogoutRedirectURI) bool {
			return r.ClientId == 42 && r.URI == uri
		})).Run(func(mock.Arguments) { note("sign-out redirect uri") }).Return(nil).Once()
	}
	auditLogger.On("Log", mock.Anything, audit.EventDynamicClientRegistration, mock.Anything).
		Run(func(mock.Arguments) { note("audit") }).Return().Once()

	rr := serveDCR(t, signOutRegistration(false,
		"https://client.example.com/signed-out", "https://client.example.com/bye?state=fixed"), database, auditLogger)

	require.Equal(t, http.StatusCreated, rr.Code)
	assert.Equal(t, []string{"begin", "client", "redirect uri", "sign-out redirect uri", "sign-out redirect uri", "commit", "audit"}, events)
	assert.Equal(t, []string{"https://client.example.com/signed-out", "https://client.example.com/bye?state=fixed"},
		decodeDCRResponse(t, rr).PostLogoutRedirectURIs)
}

// A sign-out redirect URI the engine refuses undoes the whole registration: one server_error, no
// audit event, no client answered.
func TestHandleDynamicClientRegistrationPost_AFailedSignOutRedirectURIInsertCommitsNothing(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	refused := errs.New("the engine refused the sign-out redirect URI")
	stub := datamocks.ExpectRunInTransaction(database, dcrTx)
	database.On("CreateClient", mock.Anything, dcrTx, mock.Anything).Return(nil).Once()
	database.On("CreateRedirectURI", mock.Anything, dcrTx, mock.Anything).Return(nil).Once()
	database.On("CreatePostLogoutRedirectURI", mock.Anything, dcrTx, mock.Anything).Return(refused).Once()

	rr := serveDCR(t, signOutRegistration(false, "https://client.example.com/signed-out"), database, auditLogger)

	require.ErrorIs(t, stub.BodyErr, refused)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "Failed to register client", decodeDCRError(t, rr).ErrorDescription)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// The field is optional: absent or empty, nothing is written and the answer leaves it out.
func TestHandleDynamicClientRegistrationPost_NoSignOutRedirectURIsWritesNoneAndAnswersNone(t *testing.T) {
	for name, uris := range map[string][]string{"absent": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			acceptRegistration(database, auditLogger)

			rr := serveDCR(t, signOutRegistration(false, uris...), database, auditLogger)

			require.Equal(t, http.StatusCreated, rr.Code)
			assert.NotContains(t, rr.Body.String(), "post_logout_redirect_uris")
			database.AssertNotCalled(t, "CreatePostLogoutRedirectURI", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// The list is accepted whatever the grant types, as redirect_uris is: a client_credentials-only
// registration with sign-out redirect URIs stores them.
func TestHandleDynamicClientRegistrationPost_SignOutRedirectURIsAreTakenWhateverTheGrantTypes(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	written := acceptRegistration(database, auditLogger)

	rr := serveDCR(t, oidc.DynamicClientRegistrationRequest{
		GrantTypes:             []string{"client_credentials"},
		PostLogoutRedirectURIs: []string{"https://client.example.com/signed-out"},
	}, database, auditLogger)

	require.Equal(t, http.StatusCreated, rr.Code)
	require.Len(t, *written, 1)
	assert.Equal(t, "https://client.example.com/signed-out", (*written)[0].URI)
}

// The two lists are separate: an address may be on both, and each holds 60 on its own.
func TestHandleDynamicClientRegistrationPost_TheTwoListsAreCountedApart(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	written := acceptRegistration(database, auditLogger)

	request := oidc.DynamicClientRegistrationRequest{
		RedirectURIs:           numberedSignOutURIs(60),
		PostLogoutRedirectURIs: numberedSignOutURIs(60),
	}
	rr := serveDCR(t, request, database, auditLogger)

	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	assert.Len(t, *written, 60)
}
