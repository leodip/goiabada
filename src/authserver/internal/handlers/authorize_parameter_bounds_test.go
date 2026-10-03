package handlers

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	mocks_handlers "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// These cases are the handler's half of the #437 bounds on state, nonce and scope: the
// authorization endpoint consults them on the path it owns, once to refuse through the deferral
// path and once to let a value at the bound through. They run over the real AuthorizeValidator, because a stub that
// answers "too long" would show the handler's redirect and nothing about whether it hands the
// validator the values. Every byte-level edge is protocolvalidation's table.

// newBoundedAuthorizeEndpoint is HandleAuthorizeGet over the real validator, on the endpoint's
// strict doubles: the database answers the validator's client and redirect URI reads, and a lookup
// nothing registered fails the case, which is how a scope refused before its lookups is shown.
func newBoundedAuthorizeEndpoint(t *testing.T) *authorizeEndpoint {
	t.Helper()
	e := newAuthorizeEndpoint(t)
	e.handler = HandleAuthorizeGet(e.pageRenderer, e.ceremonyStore, e.userSessionManager, e.database, nil,
		protocolvalidation.NewAuthorizeValidator(e.database), mocks_handlers.NewAuditLogger(t),
		mocks_handlers.NewPermissionChecker(t), mocks_handlers.NewTokenParser(t), testBaseURL)

	client := &record.Client{
		Id: 1, ClientIdentifier: "test-client", Enabled: true, AuthorizationCodeEnabled: true,
		DefaultAcrLevel: record.AcrLevel1,
	}
	e.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)
	e.database.On("ClientLoadRedirectURIs", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			args.Get(2).(*record.Client).RedirectURIs = []record.RedirectURI{{URI: "https://example.com"}}
		}).Return(nil)
	stubRegisteredRedirectURI(e.database, "https://example.com")
	return e
}

// stubLoggedOutBrowser answers the session reads for a browser holding no session.
func (e *authorizeEndpoint) stubLoggedOutBrowser() {
	e.database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)
	e.userSessionManager.On("HasValidUserSession", mock.Anything, mock.AnythingOfType("int"), mock.AnythingOfType("int"), mock.Anything).Return(false)
	e.database.On("UserSessionLoadUser", mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
}

// boundedQuery is a code-flow request whose parameters a case overrides.
func boundedQuery(overrides map[string]string) string {
	query := url.Values{
		"client_id":     {"test-client"},
		"redirect_uri":  {"https://example.com"},
		"response_type": {"code"},
		"scope":         {"openid"},
		"state":         {"s"},
		"nonce":         {"n"},
	}
	for name, value := range overrides {
		query.Set(name, value)
	}
	return query.Encode()
}

// distinctScopes returns n distinct resource:permission scopes of eight bytes each, so they survive
// AuthContext.SetScope's dropping of duplicates.
func distinctScopes(n int) string {
	scopes := make([]string, 0, n)
	for i := 0; i < n; i++ {
		scopes = append(scopes, fmt.Sprintf("r:p%04d", i))
	}
	return strings.Join(scopes, " ")
}

func TestHandleAuthorizeGet_AnOverlongValueIsRefusedThroughTheDeferralPath(t *testing.T) {
	overlongScope := distinctScopes(300)
	require.Greater(t, len(overlongScope), record.ScopeMaxBytes)

	cases := []struct {
		name            string
		overrides       map[string]string
		wantCode        string
		wantDescription string
		wantState       string
	}{
		{
			name:            "state",
			overrides:       map[string]string{"state": strings.Repeat("s", record.StateMaxBytes+1)},
			wantCode:        "invalid_request",
			wantDescription: fmt.Sprintf("The 'state' parameter is too long (%d bytes, the maximum is %d).", record.StateMaxBytes+1, record.StateMaxBytes),
			// RFC 6749 4.1.2.1: the refusal carries "the exact value received", however long.
			wantState: strings.Repeat("s", record.StateMaxBytes+1),
		},
		{
			name:            "nonce",
			overrides:       map[string]string{"nonce": strings.Repeat("n", record.NonceMaxBytes+1)},
			wantCode:        "invalid_request",
			wantDescription: fmt.Sprintf("The 'nonce' parameter is too long (%d bytes, the maximum is %d).", record.NonceMaxBytes+1, record.NonceMaxBytes),
			wantState:       "s",
		},
		{
			name:            "scope",
			overrides:       map[string]string{"scope": overlongScope},
			wantCode:        "invalid_scope",
			wantDescription: fmt.Sprintf("The 'scope' parameter is too long (%d bytes, the maximum is %d).", len(overlongScope), record.ScopeMaxBytes),
			wantState:       "s",
		},
	}

	for _, tc := range cases {
		// A session holder is answered at once (#213), so the refusal is on the redirect itself.
		t.Run(tc.name+", answered at once to a session holder", func(t *testing.T) {
			e := newBoundedAuthorizeEndpoint(t)
			stubAuthenticatedBrowser(e.database, e.userSessionManager)
			e.ceremonyStore.On("ClearAuthContext", mock.Anything, mock.Anything).Return(nil).Once()

			rr := e.get(t, boundedQuery(tc.overrides))

			require.Equal(t, http.StatusFound, rr.Code)
			location, err := url.Parse(rr.Header().Get("Location"))
			require.NoError(t, err)
			require.Equal(t, "example.com", location.Host)
			assert.Equal(t, tc.wantCode, location.Query().Get("error"))
			assert.Equal(t, tc.wantDescription, location.Query().Get("error_description"))
			assert.Equal(t, tc.wantState, location.Query().Get("state"))
			e.assertExpectations(t)
		})

		// A logged-out browser is not sent to the client's redirect URI on a failed request (RFC 9700
		// 4.11.2): the refusal is parked and delivered after the login.
		t.Run(tc.name+", parked behind a login for a logged-out browser", func(t *testing.T) {
			e := newBoundedAuthorizeEndpoint(t)
			e.stubLoggedOutBrowser()
			e.ceremonyStore.On("SaveAuthContext", mock.Anything, mock.Anything, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
				return ac.DeferredErrorCode == tc.wantCode && ac.DeferredErrorDescription == tc.wantDescription
			})).Return(nil).Once()

			rr := e.get(t, boundedQuery(tc.overrides))

			assertStepLocation(t, rr.Header().Get("Location"), "/auth/level1")
			e.assertExpectations(t)
		})
	}
}

// A value at the bound is served, and stored intact for the code that will carry it. The scope row
// is a leniency chosen on purpose: the bound counts the normalized scope, so a request whose raw
// scope is three times the bound in repeated, single-space-separated values is the one-value scope
// it collapses to, and is not refused.
func TestHandleAuthorizeGet_AValueAtTheBoundProceeds(t *testing.T) {
	state := strings.Repeat("s", record.StateMaxBytes)
	nonce := strings.Repeat("n", record.NonceMaxBytes)

	cases := []struct {
		name      string
		overrides map[string]string
		check     func(*testing.T, *ceremony.AuthContext)
	}{
		{
			name:      "state and nonce filling their bounds",
			overrides: map[string]string{"state": state, "nonce": nonce},
			check: func(t *testing.T, ac *ceremony.AuthContext) {
				assert.Equal(t, state, ac.State)
				assert.Equal(t, nonce, ac.Nonce)
			},
		},
		{
			name:      "a raw scope over the bound that normalizes under it",
			overrides: map[string]string{"scope": strings.TrimSuffix(strings.Repeat("openid ", 3*record.ScopeMaxBytes/len("openid ")), " ")},
			check: func(t *testing.T, ac *ceremony.AuthContext) {
				assert.Equal(t, "openid", ac.Scope)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newBoundedAuthorizeEndpoint(t)
			e.stubLoggedOutBrowser()
			e.ceremonyStore.On("SaveAuthContext", mock.Anything, mock.Anything, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
				if ac.DeferredErrorCode != "" || ac.AuthState != ceremony.AuthStateRequiresLevel1 {
					return false
				}
				tc.check(t, ac)
				return true
			})).Return(nil).Once()

			rr := e.get(t, boundedQuery(tc.overrides))

			assertStepLocation(t, rr.Header().Get("Location"), "/auth/level1",
				"the request was refused instead of going on to the login")
			e.assertExpectations(t)
		})
	}
}
