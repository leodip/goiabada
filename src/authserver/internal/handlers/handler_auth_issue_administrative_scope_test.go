package handlers

import (
	"net/http"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// /auth/issue is the last step before a code or an implicit token is minted, so an allowance
// withdrawn while a sign-in sat on a step takes effect there: a scope the issuer would read naming
// an administrative scope the client may no longer request is answered invalid_scope by redirect,
// with the sentence /auth/authorize gives the same condition, and recorded as
// administrative_scope_refused with the ceremony's user (#499 decisions 6, 7 and 9).
func TestHandleIssueGet_AnAdministrativeScopeTheClientMayNotRequestIsAnsweredInvalidScope(t *testing.T) {
	for _, tc := range []struct {
		responseType string
		inFragment   bool
	}{
		{responseType: "code"},
		{responseType: "token", inFragment: true},
	} {
		t.Run(tc.responseType, func(t *testing.T) {
			f := newRecheckFixture(t, tc.responseType, "")
			f.authContext.Scope = "openid authserver:admin-read authserver:manage"
			f.authContext.RequestedScope = f.authContext.Scope

			var order []string
			f.auditLogger.On("Log", mock.Anything, audit.EventAdministrativeScopeRefused, map[string]interface{}{
				"client_id":         int64(1),
				"client_identifier": "test-client",
				"scopes":            []string{"authserver:admin-read", "authserver:manage"},
				"checkpoint":        "issue",
				"user_id":           int64(123),
			}).Run(func(mock.Arguments) { order = append(order, "audit") }).Return().Once()
			f.ceremonyStore.On("ClearAuthContext", f.rr, f.req).
				Run(func(mock.Arguments) { order = append(order, "clear") }).Return(nil).Once()

			f.serve()

			require.Equal(t, http.StatusFound, f.rr.Code)
			params := answerParams(t, f.rr.Header().Get("Location"), tc.inFragment)
			assert.Equal(t, "invalid_scope", params.Get("error"))
			assert.Equal(t, "The client is not allowed to request the administrative scope 'authserver:admin-read'.",
				params.Get("error_description"))
			assert.Equal(t, "test-state", params.Get("state"))
			assert.Equal(t, []string{"audit", "clear"}, order)
			f.assertNothingIssued(t)
			f.database.AssertNotCalled(t, "GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, mock.Anything)
			f.auditLogger.AssertExpectations(t)
			f.ceremonyStore.AssertExpectations(t)
		})
	}
}

// The scope judged is the one the issuer would read: the consented scope when the consent screen
// wrote one, so a ceremony whose consent left the administrative scope out is issued what was
// consented, as it was before this check.
func TestHandleIssueGet_TheConsentedScopeIsWhatIsJudged(t *testing.T) {
	f := newRecheckFixture(t, "code", "")
	f.authContext.Scope = "openid authserver:manage"
	f.authContext.ConsentedScope = "openid"

	f.codeIssuer.On("IssueAuthCodeTx", mock.Anything, mock.Anything).
		Return(&record.Code{Id: 1, Code: "the-code", ClientId: 1, RedirectURI: "https://example.com/callback",
			State: "test-state"}, nil).Once()
	f.auditLogger.On("Log", mock.Anything, audit.EventCreatedAuthCode, mock.Anything).Return().Once()
	f.ceremonyStore.On("ClearAuthContext", f.rr, f.req).Return(nil).Once()

	f.serve()

	assert.Contains(t, f.rr.Header().Get("Location"), "code=the-code")
	f.auditLogger.AssertNotCalled(t, "Log", mock.Anything, audit.EventAdministrativeScopeRefused, mock.Anything)
}

// A client still allowed is issued the administrative scope, through either flow.
func TestHandleIssueGet_AnAllowedClientIsIssuedTheAdministrativeScope(t *testing.T) {
	t.Run("code", func(t *testing.T) {
		f := newRecheckFixture(t, "code", "")
		f.client.AdministrativeScopesAllowed = true
		f.authContext.Scope = "openid authserver:manage"

		f.codeIssuer.On("IssueAuthCodeTx", mock.Anything, mock.Anything).
			Return(&record.Code{Id: 1, Code: "the-code", ClientId: 1, RedirectURI: "https://example.com/callback",
				State: "test-state"}, nil).Once()
		f.auditLogger.On("Log", mock.Anything, audit.EventCreatedAuthCode, mock.Anything).Return().Once()
		f.ceremonyStore.On("ClearAuthContext", f.rr, f.req).Return(nil).Once()

		f.serve()

		assert.Contains(t, f.rr.Header().Get("Location"), "code=the-code")
	})

	t.Run("token", func(t *testing.T) {
		f := newRecheckFixture(t, "token", "")
		f.client.AdministrativeScopesAllowed = true
		f.authContext.Scope = "openid authserver:manage"

		f.implicitIssuer.On("IssueImplicitTx", mock.Anything, mock.Anything, mock.Anything, true, false).
			Return(&issuance.ImplicitGrantResponse{AccessToken: "the-token", TokenType: "Bearer", ExpiresIn: 60,
				Scope: "openid authserver:manage"}, nil).Once()
		f.auditLogger.On("Log", mock.Anything, audit.EventTokenIssuedImplicitResponse, mock.Anything).Return().Once()
		f.ceremonyStore.On("ClearAuthContext", f.rr, f.req).Return(nil).Once()

		f.serve()

		assert.Contains(t, f.rr.Header().Get("Location"), "access_token=the-token")
	})
}
