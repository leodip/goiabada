package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/uuid/uuidtest"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestValidateRedirectURI is the source of truth for what the DCR endpoint accepts as a
// redirect URI. validateRedirectURI is pure, so this table is cheap and exhaustive; the
// integration suite (dynamic_client_registration_test.go) stays deliberately thin and only
// proves the HTTP endpoint reaches this function.
//
// Every row is run against both isPublic values where the two branches differ, because the
// prefix bug this fixes (#105) was duplicated across them and a single-branch table would
// pass with half the fix.
//
// The loopback host decision itself is owned by urlmatch.IsLoopbackHost and its 38-row table
// in src/authserver/internal/urlmatch/redirect_uri_test.go. What is pinned here is that this function
// consults it, plus everything else this function decides.
func TestValidateRedirectURI(t *testing.T) {
	tests := []struct {
		uri      string
		isPublic bool
		want     bool // true = accepted
		reason   string
	}{
		// --- accepted: loopback http, public
		{"http://localhost:3000/callback", true, true, "loopback host with a port"},
		{"http://127.0.0.1:8080/callback", true, true, "IPv4 literal"},
		{"http://[::1]:9000/callback", true, true, "IPv6 literal"},
		{"http://localhost/cb", true, true, "no port"},
		{"http://127.0.0.1/cb", true, true, "IPv4, no port"},
		{"http://[::1]/cb", true, true, "IPv6, no port"},

		// --- accepted: custom schemes, public only
		{"myapp://callback", true, true, "private-use scheme"},
		{"com.example.app:/oauth", true, true, "reverse-DNS private-use scheme"},

		// Keep these two. They REVERSE the previous behaviour: the old prefix test was
		// case-sensitive, so an uppercase host was rejected. RFC 3986 section 6.2.2.1 makes
		// the host case-insensitive and urlmatch.IsLoopbackHost folds it, which is the same
		// rule the authorization path already applies (issue #41, decision 10).
		{"http://LOCALHOST/cb", true, true, "host case is not meaningful"},
		{"http://LocalHost:3000/cb", true, true, "host case is not meaningful, with a port"},

		{"http://user@localhost/cb", true, true, "userinfo: Host excludes it, so the host is still loopback"},

		// --- accepted: confidential
		{"https://app.example.com/callback", false, true, "https on any host"},
		{"http://localhost:3000/callback", false, true, "loopback http"},
		{"http://[::1]:9000/cb", false, true, "IPv6 loopback http"},

		// --- rejected: THE BUG. Each of these was accepted before, for both client types.
		{"http://localhost.attacker.com/callback", true, false, "prefix bypass, the reported case"},
		{"http://localhost.attacker.com/callback", false, false, "prefix bypass, sibling branch"},
		{"http://127.0.0.1.attacker.com/callback", true, false, "prefix bypass on the IPv4 literal"},
		{"http://127.0.0.1.attacker.com/callback", false, false, "prefix bypass on the IPv4 literal, sibling branch"},
		{"http://localhost-evil.example.net/cb", true, false, "prefix bypass with a hyphen"},
		{"http://localhost-evil.example.net/cb", false, false, "prefix bypass with a hyphen, sibling branch"},
		{"http://localhost.evil.tld:8080/cb", true, false, "prefix bypass with a port"},
		// Keep this one: it is the sharpest statement of the bug, since the prefix test did
		// not even need a separator to be fooled.
		{"http://127.0.0.1x/cb", true, false, "prefix bypass with no separator at all"},
		{"http://127.0.0.1.evil.tld/cb", false, false, "prefix bypass, sibling branch"},

		// --- rejected: pre-existing rules that must not regress
		{"https://app.example.com/callback", true, false, "public clients may not use https (issue #105 decision 7)"},
		{"http://example.com/callback", true, false, "non-loopback http"},
		{"http://example.com/callback", false, false, "non-loopback http, sibling branch"},
		{"myapp://callback", false, false, "confidential clients may not use custom schemes"},
		{"not a valid uri", true, false, "unparseable"},
		{"http:///cb", true, false, "empty host is not loopback"},

		// These two reach their rejection before urlmatch sees them, and the reason column
		// says so deliberately. url.ParseRequestURI rejects a non-numeric port outright, and
		// a parsed Host can never carry a bracketed hostname, so urlmatch's decisions 14 and
		// 15 are not reachable from this call site. Their own test file pins them.
		{"http://localhost:evil/cb", true, false, "rejected by ParseRequestURI, not by the host check"},
		{"http://127.0.0.1:80@evil.com/cb", true, false, "userinfo smuggling: the real host is evil.com"},

		// --- rejected by the absolute-URI gate (RFC 6749 section 3.1.2)
		//
		// Keep the first one verbatim. It is the only row that fails if the absolute-URI
		// gate is dropped, and it is the row whose absence leaks an authorization code:
		// a scheme-relative value is emitted as a protocol-relative Location, which the
		// user agent resolves against the current scheme. See issue #122.
		{"//evil.example/cb", true, false, "scheme-relative: the code would go to evil.example"},
		// Not load-bearing for the absolute-URI gate, and labelled so nobody assumes it is:
		// with that gate removed this row still passes, because an empty scheme is neither
		// https nor http and the confidential branch falls through to an error. Verified.
		// Kept because it documents that the confidential branch is not exposed here.
		{"//evil.example/cb", false, false, "scheme-relative; the confidential fallthrough would also reject it"},
		{"//evil.example:8443/cb", true, false, "scheme-relative with a port"},
		{"/relative/cb", true, false, "path-absolute, no scheme"},
		{"relative/cb", true, false, "rejected by ParseRequestURI, before the absolute-URI gate"},

		// --- rejected by the empty-host rule the predicate gained in #122
		//
		// These are valid absolute-URIs, so the grammar rule accepts all of them and only
		// the host rule refuses them. The confidential rows are the ones that changed
		// behaviour here: that branch returns without a host check, so before #122 this
		// endpoint registered them for any confidential client, and a browser resolving the
		// emitted Location navigates to evil.example. The public rows were already refused,
		// by IsLoopbackHost(""), and are kept to show the two branches now agree.
		{"https:///evil.example/cb", false, false, "empty authority on the confidential branch; was accepted before #122"},
		{"https:/evil.example/cb", false, false, "path-absolute https on the confidential branch; was accepted before #122"},
		{"https://///evil.example/cb", false, false, "more slashes, same empty host"},
		{"http:///evil.example/cb", true, false, "empty authority, public branch"},
		{"HTTPS:///evil.example/cb", false, false, "url.Parse lowercases the scheme, so the rule still sees https"},

		// Fragments. Each of these has a non-empty scheme, so each passes a scheme-only
		// test: they are the rows that catch that mistake. They also already malfunction
		// today, since the code is delivered to /cb%23frag rather than to the callback.
		{"http://127.0.0.1/cb#frag", true, false, "fragment on a loopback host"},
		{"https://app.example.com/cb#frag", false, false, "fragment on the confidential branch"},
		{"http://127.0.0.1/cb?a=1#f", true, false, "fragment after a query"},
		{"http://127.0.0.1/cb#", true, false, "a bare # is still a fragment component"},
		{"http://127.0.0.1/cb%23frag", true, true, "percent-encoded %23 is not a fragment delimiter"},

		// --- rejected by the character gate
		//
		// The excluded character must sit in the path, not the authority: ParseRequestURI
		// rejects these characters in a host, so an authority-position row would pass for
		// the wrong reason and would still pass with this gate deleted.
		{"x:<svg/onload=alert(1)>", true, false, "the verified admin console payload; scheme x defeats any denylist"},
		{"myapp://x<img/src=x/onerror=alert(1)>", true, false, "markup in the authority"},
		{"myapp://cb\">alert", true, false, "quote"},
		{"http://127.0.0.1/cb with space", true, false, "space"},
		{"http://127.0.0.1/cb`x`", true, false, "backtick"},
		{"http://127.0.0.1/cb{x}", true, false, "braces"},
		{"http://127.0.0.1/cb|x", true, false, "pipe"},
		{"http://127.0.0.1/cb\\x", true, false, "backslash"},
		{"http://127.0.0.1/cb^x", true, false, "caret"},
		// These two pin the gate's placement ahead of the client-type branches. Both fail
		// if it is moved inside the public custom-scheme branch, and their value is
		// invisible once the placement is right.
		{"https://app.example.com/<svg/onload=alert(1)>", false, false, "markup on an https confidential URI"},
		{"http://127.0.0.1/<svg/onload=alert(1)>", true, false, "markup on a loopback URI"},
		// Retained deliberately, labelled: this is rejected by ParseRequestURI because the
		// space is in the authority, so it is NOT a character-gate test. Do not "improve"
		// it into one.
		{"myapp://cb with space", true, false, "rejected by ParseRequestURI, not by the character gate"},

		// --- rejected by the scheme denylist
		{"javascript:alert(1)", true, false, "script execution; carries no excluded character"},
		{"JavaScript:alert(1)", true, false, "scheme comparison folds case"},
		{"vbscript:msgbox(1)", true, false, "script execution"},
		{"file:///etc/passwd", true, false, "local file access"},
		{"about:blank", true, false, "browser internal"},
		{"data:text/plain,hello", true, false, "data URI; carries no excluded character"},
		// ftp is the row that prompted extending the denylist beyond script execution: it
		// gave a public client a callback on a remote host, which is what the loopback
		// restriction exists to prevent.
		{"ftp://evil.example/cb", true, false, "remote callback for a public client"},
		{"FTP://evil.example/cb", true, false, "denylist folds case"},
		{"ws://localhost/cb", true, false, "cannot receive an authorization response"},
		{"chrome://settings", true, false, "browser internal"},
		{"view-source:http://x", true, false, "browser internal navigation primitive"},

		// --- accepted, deliberately, so the gates are not over-tightened
		{"mailto:a@b.c", true, true, "nonsensical but inert; denying merely useless schemes is taste, not security"},
		{"org.example.app.oauth://redirect", true, true, "a real private-use scheme shape"},
		{"myapp://cb/%3Cscript%3E", true, true, "percent-encoded markup is inert; innerHTML does not decode it"},
	}

	for _, tc := range tests {
		name := tc.uri
		if tc.isPublic {
			name += " [public]"
		} else {
			name += " [confidential]"
		}
		t.Run(name, func(t *testing.T) {
			err := validateRedirectURI(tc.uri, tc.isPublic)
			if tc.want {
				assert.NoError(t, err, "expected accepted (%s)", tc.reason)
			} else {
				assert.Error(t, err, "expected rejected (%s)", tc.reason)
			}
		})
	}
}

// TestGenerateDCRClientIdentifier_IsThePrefixAndAUUID pins the identifier a self-registering
// client is issued: the cosmetic dcr_ prefix the doc comment describes, then a canonical v4 from
// the generator. The identifier is what the client authenticates as from then on and what the
// clients.client_identifier unique index is taken against, so a value that is short, uppercase
// or not fresh is a collision or a lookup miss (#278).
func TestGenerateDCRClientIdentifier_IsThePrefixAndAUUID(t *testing.T) {
	first := generateDCRClientIdentifier()

	rest, found := strings.CutPrefix(first, "dcr_")
	require.True(t, found, "identifier %q must carry the dcr_ prefix", first)

	parsed, err := uuidtest.Parse(rest)
	require.NoError(t, err)
	assert.Equal(t, rest, parsed, "the generator must emit the canonical lowercase form")

	assert.NotEqual(t, first, generateDCRClientIdentifier(), "each call must draw a fresh value")
}

// RFC 6749 section 4.4 makes the client credentials grant confidential-only, and RFC 7591 section
// 2.1 names invalid_client_metadata as the answer to a registration that asks for an inconsistent
// state, so a public client asking for it is refused, alone or beside other grants, and the same
// grant lists stay accepted for either confidential method (#428).
func TestValidateDCRRequest_APublicClientCannotAskForClientCredentials(t *testing.T) {
	tests := []struct {
		authMethod string
		grants     []string
		accepted   bool
	}{
		{"none", []string{"client_credentials"}, false},
		{"none", []string{"authorization_code", "client_credentials"}, false},
		{"none", []string{"authorization_code", "refresh_token"}, true},
		{"client_secret_basic", []string{"client_credentials"}, true},
		{"client_secret_basic", []string{"authorization_code", "client_credentials"}, true},
		{"client_secret_post", []string{"client_credentials"}, true},
		{"client_secret_post", []string{"authorization_code", "client_credentials"}, true},
	}

	for _, tc := range tests {
		t.Run(tc.authMethod+" "+strings.Join(tc.grants, ","), func(t *testing.T) {
			err := validateDCRRequest(&oidc.DynamicClientRegistrationRequest{
				TokenEndpointAuthMethod: tc.authMethod,
				GrantTypes:              tc.grants,
			})
			if tc.accepted {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), "cannot use the client_credentials grant")
		})
	}
}

// sizedRedirectURI is a public client's custom-scheme redirect URI of exactly n bytes: fill repeated
// as far as it fits, then ASCII to land on n. A multi-byte fill is what makes the byte bound differ
// from a bound in runes, which would admit a 2049-byte value of emoji as about 520 characters.
func sizedRedirectURI(t *testing.T, fill string, n int) string {
	t.Helper()
	uri := "myapp://cb/"
	for len(uri)+len(fill) <= n {
		uri += fill
	}
	uri += strings.Repeat("a", n-len(uri))
	require.Len(t, uri, n, "the case must sit exactly on its byte count")
	return uri
}

// The redirect URI bounds are storage's (record.RedirectURIsMaxPerClient, RedirectURIMaxBytes) and
// every refusal is the "check redirect_uris" one, so each row is one list varied from an accepted
// one by the thing under test (#428).
func TestValidateDCRRedirectURIs_Bounds(t *testing.T) {
	uris := func(n int) []string {
		list := make([]string, n)
		for i := range list {
			list[i] = fmt.Sprintf("myapp://cb/%d", i)
		}
		return list
	}

	tests := []struct {
		name     string
		uris     []string
		accepted bool
		message  string
	}{
		{"60 URIs", uris(60), true, ""},
		{"61 URIs", uris(61), false, "more than 60 entries"},
		{"2048 bytes of ASCII", []string{sizedRedirectURI(t, "a", 2048)}, true, ""},
		{"2049 bytes of ASCII", []string{sizedRedirectURI(t, "a", 2049)}, false, "exceed 2048 bytes"},
		{"2048 bytes of two-byte characters", []string{sizedRedirectURI(t, "é", 2048)}, true, ""},
		{"2049 bytes of two-byte characters", []string{sizedRedirectURI(t, "é", 2049)}, false, "exceed 2048 bytes"},
		{"2048 bytes of four-byte characters", []string{sizedRedirectURI(t, "😀", 2048)}, true, ""},
		{"2049 bytes of four-byte characters", []string{sizedRedirectURI(t, "😀", 2049)}, false, "exceed 2048 bytes"},
		{"a URI listed twice", []string{"myapp://cb/a", "myapp://cb/b", "myapp://cb/a"}, false, "listed more than once"},
		{"two URIs differing only in case", []string{"myapp://cb/A", "myapp://cb/a"}, true, ""},
		// Also malformed, and answered with the length: the bound is checked before anything
		// parses the value.
		{"an overlong value that is also malformed", []string{"not a uri " + strings.Repeat("a", 2040)}, false, "exceed 2048 bytes"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDCRRedirectURIs(&oidc.DynamicClientRegistrationRequest{
				TokenEndpointAuthMethod: "none",
				GrantTypes:              []string{"authorization_code"},
				RedirectURIs:            tc.uris,
			})
			if tc.accepted {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.message)
		})
	}
}

// dcrTx is the transaction the stub hands the registration's body, so a write asserted on it is
// one made inside the transaction and not one moved back outside it.
var dcrTx = &sql.Tx{}

func serveDCR(t *testing.T, request oidc.DynamicClientRegistrationRequest,
	database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) *httptest.ResponseRecorder {

	t.Helper()
	body, err := json.Marshal(request)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/connect/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{Id: 1, DynamicClientRegistrationEnabled: true}))

	rr := httptest.NewRecorder()
	HandleDynamicClientRegistrationPost(database, auditLogger, testDataCipher).ServeHTTP(rr, req)
	return rr
}

func decodeDCRError(t *testing.T, rr *httptest.ResponseRecorder) oidc.DynamicClientRegistrationError {
	t.Helper()
	var envelope oidc.DynamicClientRegistrationError
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &envelope))
	return envelope
}

// decodeDCRResponse reads the 201 body the handler wrote, with the headers RFC 7591 section 3.2.1
// and RFC 6749 section 5.1 require on a response carrying a client secret.
func decodeDCRResponse(t *testing.T, rr *httptest.ResponseRecorder) oidc.DynamicClientRegistrationResponse {
	t.Helper()
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))
	var response oidc.DynamicClientRegistrationResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
	return response
}

var confidentialTwoURIRegistration = oidc.DynamicClientRegistrationRequest{
	ClientName:   "A Test Client",
	RedirectURIs: []string{"https://client.example.com/one", "https://client.example.com/two"},
}

// The client and every redirect URI are written on the one transaction, and the audit event
// follows its commit, so an event never names a client that was rolled back (#428).
func TestHandleDynamicClientRegistrationPost_WritesTheClientAndItsRedirectURIsInOneTransaction(t *testing.T) {
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
	for _, uri := range confidentialTwoURIRegistration.RedirectURIs {
		database.On("CreateRedirectURI", mock.Anything, dcrTx, mock.MatchedBy(func(r *record.RedirectURI) bool {
			return r.ClientId == 42 && r.URI == uri
		})).Run(func(mock.Arguments) { note("redirect uri") }).Return(nil).Once()
	}
	auditLogger.On("Log", mock.Anything, audit.EventDynamicClientRegistration, mock.Anything).
		Run(func(mock.Arguments) { note("audit") }).Return().Once()

	rr := serveDCR(t, confidentialTwoURIRegistration, database, auditLogger)

	assert.Equal(t, http.StatusCreated, rr.Code)
	assert.Equal(t, []string{"begin", "client", "redirect uri", "redirect uri", "commit", "audit"}, events)
	response := decodeDCRResponse(t, rr)
	assert.NotEmpty(t, response.ClientID)
	assert.NotEmpty(t, response.ClientSecret, "a confidential client is answered its secret")
	assert.Equal(t, confidentialTwoURIRegistration.RedirectURIs, response.RedirectURIs)
}

// What the compensating delete used to stand for, now the transaction's: the second redirect URI
// failing hands the helper an error, which is what rolls back the client and the first URI, and the
// requester gets one server_error with nothing audited and no registration answered.
func TestHandleDynamicClientRegistrationPost_AFailedSecondInsertCommitsNothing(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	refused := errs.New("the engine refused the second redirect URI")
	stub := datamocks.ExpectRunInTransaction(database, dcrTx)
	database.On("CreateClient", mock.Anything, dcrTx, mock.Anything).Return(nil).Once()
	database.On("CreateRedirectURI", mock.Anything, dcrTx, mock.Anything).Return(nil).Once()
	database.On("CreateRedirectURI", mock.Anything, dcrTx, mock.Anything).Return(refused).Once()

	rr := serveDCR(t, confidentialTwoURIRegistration, database, auditLogger)

	require.ErrorIs(t, stub.BodyErr, refused, "the body handed the helper the failure, so nothing was committed")
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	envelope := decodeDCRError(t, rr)
	assert.Equal(t, "server_error", envelope.Error)
	assert.Equal(t, "Failed to register client", envelope.ErrorDescription)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	assert.NotContains(t, rr.Body.String(), "client_id", "no registration is answered")
}

func TestHandleDynamicClientRegistrationPost_AFailedClientInsertWritesNoRedirectURI(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	refused := errs.New("the engine refused the client")
	stub := datamocks.ExpectRunInTransaction(database, dcrTx)
	database.On("CreateClient", mock.Anything, dcrTx, mock.Anything).Return(refused).Once()

	rr := serveDCR(t, confidentialTwoURIRegistration, database, auditLogger)

	require.ErrorIs(t, stub.BodyErr, refused)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "Failed to register client", decodeDCRError(t, rr).ErrorDescription)
	database.AssertNotCalled(t, "CreateRedirectURI", mock.Anything, mock.Anything, mock.Anything)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// A public client is written through the one public-client rule: PKCE an explicit true, client
// credentials off (#245, #428).
func TestHandleDynamicClientRegistrationPost_APublicClientIsWrittenWithThePublicClientInvariants(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	datamocks.ExpectRunInTransaction(database, dcrTx)
	database.On("CreateClient", mock.Anything, dcrTx, mock.MatchedBy(func(c *record.Client) bool {
		return c.IsPublic && c.PKCERequired != nil && *c.PKCERequired && !c.ClientCredentialsEnabled
	})).Return(nil).Once()
	database.On("CreateRedirectURI", mock.Anything, dcrTx, mock.Anything).Return(nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventDynamicClientRegistration, mock.Anything).Return().Once()

	rr := serveDCR(t, oidc.DynamicClientRegistrationRequest{
		ClientName:              "A Public Client",
		RedirectURIs:            []string{"http://127.0.0.1:8765/callback"},
		TokenEndpointAuthMethod: "none",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
	}, database, auditLogger)

	assert.Equal(t, http.StatusCreated, rr.Code)
	response := decodeDCRResponse(t, rr)
	assert.Equal(t, "none", response.TokenEndpointAuthMethod)
	assert.Empty(t, response.ClientSecret, "a public client is answered no secret")
}

// A self-registered client has both legacy flows off on the client itself. Left unset, each switch
// followed the global one, so turning the implicit flow or ROPC on under Admin, General gave it to
// every client anyone had registered, though a registration asking for either is refused. Found
// reviewing the DCR docs before 1.7.0.
func TestHandleDynamicClientRegistrationPost_ASelfRegisteredClientNeverInheritsTheLegacyFlows(t *testing.T) {
	for _, authMethod := range []string{"none", "client_secret_basic"} {
		t.Run(authMethod, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			var created *record.Client
			datamocks.ExpectRunInTransaction(database, dcrTx)
			database.On("CreateClient", mock.Anything, dcrTx, mock.Anything).
				Run(func(args mock.Arguments) { created = args.Get(2).(*record.Client) }).Return(nil).Once()
			database.On("CreateRedirectURI", mock.Anything, dcrTx, mock.Anything).Return(nil).Once()
			auditLogger.On("Log", mock.Anything, audit.EventDynamicClientRegistration, mock.Anything).Return().Once()

			rr := serveDCR(t, oidc.DynamicClientRegistrationRequest{
				RedirectURIs:            []string{"http://127.0.0.1:8765/callback"},
				TokenEndpointAuthMethod: authMethod,
			}, database, auditLogger)

			require.Equal(t, http.StatusCreated, rr.Code)
			require.NotNil(t, created)
			require.NotNil(t, created.ImplicitGrantEnabled, "the implicit switch must be set, not left to the global one")
			require.NotNil(t, created.ResourceOwnerPasswordCredentialsEnabled, "the ROPC switch must be set, not left to the global one")
			assert.False(t, *created.ImplicitGrantEnabled)
			assert.False(t, *created.ResourceOwnerPasswordCredentialsEnabled)
			assert.False(t, created.IsImplicitGrantEnabled(true), "the global implicit setting on doesn't reach it")
			assert.False(t, created.IsResourceOwnerPasswordCredentialsEnabled(true), "the global ROPC setting on doesn't reach it")
		})
	}
}

// The registration's audit entry records the client IP through the module's one reader, so it
// names the address every other audit entry names: httptest's "192.0.2.1:1234" is recorded as
// "192.0.2.1". This handler returned r.RemoteAddr as is until #435.
func TestHandleDynamicClientRegistrationPost_AuditsTheClientIPWithoutItsPort(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	datamocks.ExpectRunInTransaction(database, dcrTx)
	database.On("CreateClient", mock.Anything, dcrTx, mock.Anything).Return(nil).Once()
	database.On("CreateRedirectURI", mock.Anything, dcrTx, mock.Anything).Return(nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventDynamicClientRegistration,
		mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["ip"] == "192.0.2.1"
		})).Return().Once()

	rr := serveDCR(t, oidc.DynamicClientRegistrationRequest{
		ClientName:              "A Public Client",
		RedirectURIs:            []string{"http://127.0.0.1:8765/callback"},
		TokenEndpointAuthMethod: "none",
		GrantTypes:              []string{"authorization_code"},
	}, database, auditLogger)

	assert.Equal(t, http.StatusCreated, rr.Code)
}

// Every refusal is decided before the transaction opens, so none reaches RunInTransaction: the
// strict mock has no expectation for it and would fail the case if it were called (#428).
func TestHandleDynamicClientRegistrationPost_ARefusalNeverReachesTheTransaction(t *testing.T) {
	manyURIs := make([]string, record.RedirectURIsMaxPerClient+1)
	for i := range manyURIs {
		manyURIs[i] = fmt.Sprintf("https://client.example.com/%d", i)
	}

	tests := []struct {
		name    string
		request oidc.DynamicClientRegistrationRequest
		code    string
	}{
		{"a public client asking for client_credentials", oidc.DynamicClientRegistrationRequest{
			RedirectURIs:            []string{"http://127.0.0.1:8765/callback"},
			TokenEndpointAuthMethod: "none",
			GrantTypes:              []string{"authorization_code", "client_credentials"},
		}, oidc.DCRErrorInvalidClientMetadata},
		// The two grants oidc's grant table knows but marks not registrable; the table's rows are
		// pinned in grant_type_test.go, and these show DCR consults it (#437).
		{"the password grant", oidc.DynamicClientRegistrationRequest{
			RedirectURIs: []string{"https://client.example.com/cb"},
			GrantTypes:   []string{"authorization_code", "password"},
		}, oidc.DCRErrorInvalidClientMetadata},
		{"the implicit grant", oidc.DynamicClientRegistrationRequest{
			RedirectURIs: []string{"https://client.example.com/cb"},
			GrantTypes:   []string{"implicit"},
		}, oidc.DCRErrorInvalidClientMetadata},
		{"one redirect URI past the count", oidc.DynamicClientRegistrationRequest{
			RedirectURIs: manyURIs,
		}, oidc.DCRErrorInvalidRedirectURI},
		{"a redirect URI one byte past the length", oidc.DynamicClientRegistrationRequest{
			RedirectURIs: []string{"https://client.example.com/" + strings.Repeat("a", record.RedirectURIMaxBytes+1-len("https://client.example.com/"))},
		}, oidc.DCRErrorInvalidRedirectURI},
		{"a redirect URI listed twice", oidc.DynamicClientRegistrationRequest{
			RedirectURIs: []string{"https://client.example.com/cb", "https://client.example.com/cb"},
		}, oidc.DCRErrorInvalidRedirectURI},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)

			rr := serveDCR(t, tc.request, database, handlersmocks.NewAuditLogger(t))

			assert.Equal(t, http.StatusBadRequest, rr.Code)
			assert.Equal(t, tc.code, decodeDCRError(t, rr).Error)
			database.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
		})
	}
}

// A description interpolating request text is conformed like the authorization and token
// endpoints': RFC 7591 section 3.2.2 makes it ASCII, and RFC 6749 Appendix A.8's NQSCHAR is what the
// conformer admits, bounded to 512 bytes. The value is 3000 bytes carrying a double quote, a
// backslash and a non-ASCII character, which before this came back as a 3029-byte description with
// all three in it (#428).
func TestHandleDynamicClientRegistrationPost_ADescriptionEchoingRequestTextIsConformed(t *testing.T) {
	grantType := `x"y\z é ` + strings.Repeat("a", 3000-len(`x"y\z é `))
	require.Len(t, grantType, 3000)

	rr := serveDCR(t, oidc.DynamicClientRegistrationRequest{
		RedirectURIs: []string{"https://client.example.com/cb"},
		GrantTypes:   []string{grantType},
	}, datamocks.NewDatabase(t), handlersmocks.NewAuditLogger(t))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	envelope := decodeDCRError(t, rr)
	assert.Equal(t, oidc.DCRErrorInvalidClientMetadata, envelope.Error)
	assert.True(t, strings.HasPrefix(envelope.ErrorDescription, "unsupported grant_type: x?y?z ? "),
		"each forbidden character is replaced, not dropped: %q", envelope.ErrorDescription[:40])
	assert.LessOrEqual(t, len(envelope.ErrorDescription), 512)
	for i := 0; i < len(envelope.ErrorDescription); i++ {
		b := envelope.ErrorDescription[i]
		assert.True(t, b >= 0x20 && b <= 0x7E && b != '"' && b != '\\',
			"byte %#x at %d is outside RFC 6749 Appendix A.8's NQSCHAR", b, i)
	}
}

// Every refusal writes one Warn record with the code and description the registrant was answered
// with. Checking the demo's registrations against the docs found the request log's status the only
// trace of six refused registrations, so an operator could not tell a misconfigured tool's wrong
// redirect URI from a server taking no registrations at all.
func TestHandleDynamicClientRegistrationPost_EveryRefusalIsLoggedAtWarn(t *testing.T) {
	publicAskingClientCredentials, err := json.Marshal(oidc.DynamicClientRegistrationRequest{
		RedirectURIs:            []string{"http://127.0.0.1:8765/callback"},
		TokenEndpointAuthMethod: "none",
		GrantTypes:              []string{"client_credentials"},
	})
	require.NoError(t, err)
	publicWithHTTPS, err := json.Marshal(oidc.DynamicClientRegistrationRequest{
		RedirectURIs:            []string{"https://spa.example.com/cb"},
		TokenEndpointAuthMethod: "none",
	})
	require.NoError(t, err)

	tests := []struct {
		name    string
		enabled bool
		body    string
		status  int
		code    string
		reason  string
	}{
		{"registration turned off", false, string(publicWithHTTPS), http.StatusForbidden,
			"access_denied", "Dynamic client registration is not enabled"},
		{"a body that isn't JSON", true, "{", http.StatusBadRequest,
			oidc.DCRErrorInvalidClientMetadata, "Invalid request body"},
		{"metadata the server refuses", true, string(publicAskingClientCredentials), http.StatusBadRequest,
			oidc.DCRErrorInvalidClientMetadata, "a public client (token_endpoint_auth_method none) cannot use the client_credentials grant"},
		{"a redirect URI the server refuses", true, string(publicWithHTTPS), http.StatusBadRequest,
			oidc.DCRErrorInvalidRedirectURI, "public clients registered via DCR cannot use https redirect_uris (security restriction): https://spa.example.com/cb"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logs := logtest.CaptureSlog(t)
			req := httptest.NewRequest(http.MethodPost, "/connect/register", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req = req.WithContext(reqctx.WithSettings(req.Context(),
				&record.Settings{Id: 1, DynamicClientRegistrationEnabled: tc.enabled}))
			rr := httptest.NewRecorder()

			HandleDynamicClientRegistrationPost(datamocks.NewDatabase(t), handlersmocks.NewAuditLogger(t),
				testDataCipher).ServeHTTP(rr, req)

			assert.Equal(t, tc.status, rr.Code)
			assert.Equal(t, tc.code, decodeDCRError(t, rr).Error)
			records := logs.Records()
			require.Len(t, records, 1)
			assert.Equal(t, slog.LevelWarn, records[0].Level)
			assert.Equal(t, "client registration refused", records[0].Message)
			assert.Equal(t, tc.code, records[0].Attrs["error_code"])
			assert.Equal(t, tc.reason, records[0].Attrs["reason"])
		})
	}
}

// The two tests below drive writeDCRResponse directly, the only tests in this file below the
// handler seam. DynamicClientRegistrationResponse holds strings, ints and string slices and cannot
// fail to marshal, so no request reaches either branch through the handler (#435).

// A body that cannot be encoded is answered in RFC 7591 section 3.2.2's envelope with a 500, one
// record, and no 201: the encode runs before anything is written.
func TestWriteDCRResponse_AnUnencodableBodyAnswersTheRFC7591Envelope(t *testing.T) {
	logs := logtest.CaptureSlog(t)
	rr := httptest.NewRecorder()

	writeDCRResponse(rr, httptest.NewRequest(http.MethodPost, "/connect/register", nil), func() {})

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	envelope := decodeDCRError(t, rr)
	assert.Equal(t, "server_error", envelope.Error)
	assert.Equal(t, "Internal server error", envelope.ErrorDescription)

	records := logs.Records()
	require.Len(t, records, 1)
	assert.Equal(t, slog.LevelError, records[0].Level)
	assert.Equal(t, "internal server error", records[0].Message)
	logged, isError := records[0].Attrs["error"].(error)
	require.True(t, isError, "the error attribute must carry the error value itself")
	var unsupported *json.UnsupportedTypeError
	assert.ErrorAs(t, logged, &unsupported)
}

// Once the 201 is committed a failed write has nothing left to answer, so it is a Debug record and
// never an Error one.
func TestWriteDCRResponse_AFailedWriteIsDebug(t *testing.T) {
	logs := logtest.CaptureSlog(t)
	rr := failingBodyRecorder{httptest.NewRecorder()}

	writeDCRResponse(rr, httptest.NewRequest(http.MethodPost, "/connect/register", nil),
		oidc.DynamicClientRegistrationResponse{ClientID: "a-client"})

	assert.Equal(t, http.StatusCreated, rr.Code)
	records := logs.Records()
	require.Len(t, records, 1)
	assert.Equal(t, slog.LevelDebug, records[0].Level)
	assert.Equal(t, "unable to write the registration response", records[0].Message)
	logged, isError := records[0].Attrs["error"].(error)
	require.True(t, isError, "the error attribute must carry the error value itself")
	assert.ErrorIs(t, logged, errBodyWriteRefused)
}

// client_name is stored as the client's description, so it takes the admin API's description
// bound, 100, rather than the column's 128: a longer name made a client whose Settings tab could
// not be saved. Found reviewing the Clients page before 1.7.0.
func TestValidateDCRRequest_AClientNameTakesTheDescriptionBound(t *testing.T) {
	atBound := oidc.DynamicClientRegistrationRequest{ClientName: strings.Repeat("a", 100)}
	applyDCRDefaults(&atBound)
	require.NoError(t, validateDCRRequest(&atBound))

	pastBound := oidc.DynamicClientRegistrationRequest{ClientName: strings.Repeat("a", 101)}
	applyDCRDefaults(&pastBound)
	require.ErrorContains(t, validateDCRRequest(&pastBound), "client_name cannot exceed 100 characters")
}
