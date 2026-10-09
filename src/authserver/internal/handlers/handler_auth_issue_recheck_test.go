package handlers

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"testing/fstest"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
)

// Seam 4 of #437 for /auth/issue's re-checks and for the implicit grant's transaction: each outcome
// decideIssuance reaches (its own table is handler_auth_issue_decide_test.go's) arrives at the act
// it names, and the acts keep the order every refusal here owes, the clear before the answer
// (#141). Nothing is issued in any refusal below, and that is enforced rather than asserted: the
// two issuers are strict mocks with no expectation, so reaching either fails the case on its own.

// recheckGeneration is the authentication generation the ceremonies below authenticated at, and the
// one their user holds unless a case moves it.
const recheckGeneration = 5

type recheckFixture struct {
	pageRenderer   *handlersmocks.PageRenderer
	ceremonyStore  *handlersmocks.CeremonyStore
	codeIssuer     *handlersmocks.CodeIssuer
	implicitIssuer *handlersmocks.ImplicitTokenIssuer
	database       *datamocks.Database
	auditLogger    *handlersmocks.AuditLogger
	settings       *record.Settings
	client         *record.Client
	user           *record.User
	authContext    *ceremony.AuthContext
	req            *http.Request
	rr             *httptest.ResponseRecorder
	serve          func()
}

// newRecheckFixture is a ceremony that passes every check: an enabled client allowed both flows, an
// enabled user at the generation the ceremony authenticated at, and a live, owned, valid session.
// Every read is Maybe(), because a case refused early reaches none of the later ones; a case that
// must not reach one says so with AssertNotCalled. A case edits f.client, f.user or f.settings
// before f.serve(): the mocks hand out those pointers.
func newRecheckFixture(t *testing.T, responseType string, prompt string) *recheckFixture {
	t.Helper()
	return newRecheckFixtureFor(t, responseType, prompt, liveSessionIdentifier)
}

// newRecheckFixtureFor is newRecheckFixture for a request that resolved the given session identifier,
// none when it is empty.
func newRecheckFixtureFor(t *testing.T, responseType string, prompt string, sessionIdentifier string) *recheckFixture {
	t.Helper()

	const callback = "https://example.com/callback"

	f := &recheckFixture{
		pageRenderer:   handlersmocks.NewPageRenderer(t),
		ceremonyStore:  handlersmocks.NewCeremonyStore(t),
		codeIssuer:     handlersmocks.NewCodeIssuer(t),
		implicitIssuer: handlersmocks.NewImplicitTokenIssuer(t),
		database:       datamocks.NewDatabase(t),
		auditLogger:    handlersmocks.NewAuditLogger(t),
		settings: &record.Settings{
			UserSessionIdleTimeoutInSeconds: testIdleTimeoutInSeconds,
			UserSessionMaxLifetimeInSeconds: testMaxLifetimeInSeconds,
		},
		client: &record.Client{Id: 1, ClientIdentifier: "test-client", Enabled: true,
			AuthorizationCodeEnabled: true, ImplicitGrantEnabled: &implicitAllowed},
		user: &record.User{Id: 123, Subject: "11111111-1111-1111-1111-111111111111", Enabled: true,
			AuthStateGeneration: recheckGeneration},
		authContext: &ceremony.AuthContext{
			CeremonyId:          testCeremonyId,
			AuthState:           ceremony.AuthStateReadyToIssueCode,
			ClientId:            "test-client",
			UserId:              123,
			ResponseType:        responseType,
			RedirectURI:         callback,
			Scope:               "openid",
			RequestedScope:      "openid",
			State:               "test-state",
			Nonce:               "test-nonce",
			AcrLevel:            record.AcrLevel1,
			AuthMethods:         "pwd",
			Prompt:              prompt,
			AuthStateGeneration: recheckGeneration,
		},
		rr: httptest.NewRecorder(),
	}

	req, err := http.NewRequest("GET", "/auth/issue?ceremony="+testCeremonyId, nil)
	require.NoError(t, err)
	req = withSettings(req, f.settings)
	if sessionIdentifier != "" {
		req = req.WithContext(reqctx.WithSessionIdentifier(req.Context(), sessionIdentifier))
	}
	f.req = req
	f.ceremonyStore.On("GetAuthContext", f.req).Return(f.authContext, nil)

	f.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
		Return(f.client, nil).Maybe()
	f.database.On("ClientLoadRedirectURIs", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			args.Get(2).(*record.Client).RedirectURIs = []record.RedirectURI{{URI: callback}}
		}).Return(nil).Maybe()
	f.database.On("GetRedirectURIsByClientId", mock.Anything, mock.Anything, mock.Anything).
		Return([]record.RedirectURI{{URI: callback}}, nil).Maybe()
	f.database.On("GetUserById", mock.Anything, mock.Anything, int64(123)).Return(f.user, nil).Maybe()
	f.database.On("GetUserSessionBySessionIdentifier", mock.Anything, (*sql.Tx)(nil), liveSessionIdentifier).
		Return(&record.UserSession{Id: 55, SessionIdentifier: liveSessionIdentifier, UserId: 123}, nil).Maybe()

	userSessionManager := handlersmocks.NewUserSessionManager(t)
	// As the real manager answers: a row that does not resolve is not valid.
	userSessionManager.On("HasValidUserSession", mock.Anything, testIdleTimeoutInSeconds, testMaxLifetimeInSeconds, mock.Anything).
		Return(func(session *record.UserSession, _ int, _ int, _ *int64) bool { return session != nil }).Maybe()
	permissionChecker := handlersmocks.NewPermissionChecker(t)
	permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", mock.Anything, mock.Anything, mock.Anything).
		Return(func(_ context.Context, scope string, _ *record.User) string { return scope }, nil).Maybe()

	handler := HandleIssueGet(f.pageRenderer, f.ceremonyStore, fstest.MapFS{}, f.codeIssuer, f.implicitIssuer,
		f.database, f.auditLogger, userSessionManager, permissionChecker, testTokenMetrics(), testBaseURL, testAdminConsoleBaseURL)
	f.serve = func() { handler.ServeHTTP(f.rr, f.req) }
	return f
}

// assertNothingIssued names what the strict mocks already enforce, and that a refusal reads nothing
// after the check that refused: the session and the user are the reads a later check would make.
func (f *recheckFixture) assertNothingIssued(t *testing.T) {
	t.Helper()
	f.codeIssuer.AssertNotCalled(t, "IssueAuthCodeTx", mock.Anything, mock.Anything)
	f.implicitIssuer.AssertNotCalled(t, "IssueImplicitTx", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// answerParams is the parameters of the redirect the client was sent, from the fragment for an
// implicit ceremony and the query for a code one.
func answerParams(t *testing.T, location string, inFragment bool) url.Values {
	t.Helper()
	parsed, err := url.Parse(location)
	require.NoError(t, err)
	if inFragment {
		values, parseErr := url.ParseQuery(parsed.Fragment)
		require.NoError(t, parseErr)
		assert.Empty(t, parsed.RawQuery, "an implicit answer carries nothing in the query")
		return values
	}
	assert.Empty(t, parsed.Fragment, "a code answer carries nothing in the fragment")
	return parsed.Query()
}

// The client itself is refused, so the answer is the page /auth/authorize renders for a disabled
// client and never a redirect: answering the client is what disabling it stops (decision 17). It
// is cleared first, as every refusal here is, and the page is rendered whether or not the clear
// succeeds, since it reaches no client.
func TestHandleIssueGet_ADisabledClientIsRefusedOnThePage(t *testing.T) {
	for _, responseType := range []string{"code", "token", "id_token token"} {
		t.Run(responseType+", the clear succeeds", func(t *testing.T) {
			f := newRecheckFixture(t, responseType, "")
			f.client.Enabled = false

			var order []string
			f.ceremonyStore.On("ClearAuthContext", f.rr, f.req).
				Run(func(mock.Arguments) { order = append(order, "clear") }).Return(nil).Once()
			wantMessage := i18n.NewLocalizedError(i18n.ErrCodeAuthorizeClientDisabled, nil).Localize(f.req.Context())
			f.pageRenderer.On("RenderTemplate", f.rr, f.req, "/layouts/no_menu_layout.html", "/auth_error.html",
				mock.MatchedBy(func(bind map[string]interface{}) bool {
					return bind["error"] == wantMessage && bind["_httpStatus"] == http.StatusOK
				})).Run(func(mock.Arguments) { order = append(order, "render") }).Return(nil).Once()

			f.serve()

			assert.Equal(t, []string{"clear", "render"}, order)
			assert.Contains(t, wantMessage, "disabled", "the page says why")
			assert.Empty(t, f.rr.Header().Get("Location"), "the client is not answered")
			f.assertNothingIssued(t)
			f.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
			// Nothing after the check that refused was read: not the user, not the session.
			f.database.AssertNotCalled(t, "GetUserById", mock.Anything, mock.Anything, mock.Anything)
			f.database.AssertNotCalled(t, "GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, mock.Anything)
			f.pageRenderer.AssertExpectations(t)
			f.ceremonyStore.AssertExpectations(t)
		})
	}

	t.Run("a failed clear still renders the page, and says so", func(t *testing.T) {
		f := newRecheckFixture(t, "code", "")
		f.client.Enabled = false
		logs := logtest.CaptureSlog(t)

		f.ceremonyStore.On("ClearAuthContext", f.rr, f.req).Return(errs.New("the store is unreachable")).Once()
		f.pageRenderer.On("RenderTemplate", f.rr, f.req, "/layouts/no_menu_layout.html", "/auth_error.html", mock.Anything).
			Return(nil).Once()

		f.serve()

		assert.Empty(t, f.rr.Header().Get("Location"))
		var logged bool
		for _, logRecord := range logs.Records() {
			logged = logged || (logRecord.Level.String() == "ERROR" &&
				logRecord.Message == "unable to clear the auth context while refusing a disabled client, rendering the refusal anyway")
		}
		assert.True(t, logged, "the failed clear is an Error record")
		f.pageRenderer.AssertExpectations(t)
	})
}

// A flow the operator switched off for the client since the ceremony began is answered
// unauthorized_client by redirect, in the ceremony's own response mode and with the sentence the
// authorize and token endpoints give the same condition (decision 17).
func TestHandleIssueGet_AFlowSwitchedOffIsAnsweredUnauthorizedClient(t *testing.T) {
	off := false

	testCases := []struct {
		name         string
		responseType string
		edit         func(f *recheckFixture)
		description  string
		inFragment   bool
	}{
		{
			name: "implicit, off for this client while on globally", responseType: "token",
			edit: func(f *recheckFixture) {
				f.client.ImplicitGrantEnabled = &off
				f.settings.ImplicitFlowEnabled = true
			},
			description: protocolvalidation.ImplicitNotAuthorizedErrorMsg, inFragment: true,
		},
		{
			name: "implicit, off globally and the client sets no override", responseType: "id_token",
			edit: func(f *recheckFixture) {
				f.client.ImplicitGrantEnabled = nil
				f.settings.ImplicitFlowEnabled = false
			},
			description: protocolvalidation.ImplicitNotAuthorizedErrorMsg, inFragment: true,
		},
		{
			name: "implicit, both tokens", responseType: "id_token token",
			edit:        func(f *recheckFixture) { f.client.ImplicitGrantEnabled = &off },
			description: protocolvalidation.ImplicitNotAuthorizedErrorMsg, inFragment: true,
		},
		{
			name: "the authorization code flow", responseType: "code",
			edit:        func(f *recheckFixture) { f.client.AuthorizationCodeEnabled = false },
			description: protocolvalidation.AuthorizationCodeNotSupportedErrorMsg, inFragment: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name+", the client is answered and the context is cleared first", func(t *testing.T) {
			f := newRecheckFixture(t, tc.responseType, "")
			tc.edit(f)

			var order []string
			f.ceremonyStore.On("ClearAuthContext", f.rr, f.req).
				Run(func(mock.Arguments) { order = append(order, "clear") }).Return(nil).Once()

			f.serve()

			require.Equal(t, http.StatusFound, f.rr.Code)
			params := answerParams(t, f.rr.Header().Get("Location"), tc.inFragment)
			assert.Equal(t, "unauthorized_client", params.Get("error"))
			assert.Equal(t, tc.description, params.Get("error_description"))
			assert.Equal(t, "test-state", params.Get("state"))
			assert.Equal(t, []string{"clear"}, order)
			f.assertNothingIssued(t)
			f.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
			f.database.AssertNotCalled(t, "GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, mock.Anything)
			f.ceremonyStore.AssertExpectations(t)
		})

		t.Run(tc.name+", a failed clear answers server_error instead", func(t *testing.T) {
			f := newRecheckFixture(t, tc.responseType, "")
			tc.edit(f)

			f.ceremonyStore.On("ClearAuthContext", f.rr, f.req).Return(errs.New("the store is unreachable")).Once()

			f.serve()

			require.Equal(t, http.StatusFound, f.rr.Code)
			params := answerParams(t, f.rr.Header().Get("Location"), tc.inFragment)
			assert.Equal(t, "server_error", params.Get("error"))
			f.assertNothingIssued(t)
		})
	}

	// One switch never refuses the other flow's ceremony (decision 17: each ceremony is checked
	// against its own flow), so a code ceremony issues with the implicit grant off, and an implicit
	// one with the code flow off.
	t.Run("the implicit grant off does not refuse a code ceremony", func(t *testing.T) {
		f := newRecheckFixture(t, "code", "")
		f.client.ImplicitGrantEnabled = &off

		f.codeIssuer.On("IssueAuthCodeTx", mock.Anything, mock.Anything).
			Return(&record.Code{Id: 1, Code: "the-code", ClientId: 1, RedirectURI: "https://example.com/callback",
				State: "test-state"}, nil).Once()
		f.auditLogger.On("Log", mock.Anything, audit.EventCreatedAuthCode, mock.Anything).Return().Once()
		f.ceremonyStore.On("ClearAuthContext", f.rr, f.req).Return(nil).Once()

		f.serve()

		assert.Contains(t, f.rr.Header().Get("Location"), "code=the-code")
		f.codeIssuer.AssertExpectations(t)
	})

	t.Run("the code flow off does not refuse an implicit ceremony", func(t *testing.T) {
		f := newRecheckFixture(t, "token", "")
		f.client.AuthorizationCodeEnabled = false

		f.implicitIssuer.On("IssueImplicitTx", mock.Anything, mock.Anything, mock.Anything, true, false).
			Return(&issuance.ImplicitGrantResponse{AccessToken: "the-token", TokenType: "Bearer", ExpiresIn: 60, Scope: "openid"}, nil).Once()
		f.auditLogger.On("Log", mock.Anything, audit.EventTokenIssuedImplicitResponse, mock.Anything).Return().Once()
		f.ceremonyStore.On("ClearAuthContext", f.rr, f.req).Return(nil).Once()

		f.serve()

		assert.Contains(t, f.rr.Header().Get("Location"), "access_token=the-token")
		f.implicitIssuer.AssertExpectations(t)
	})
}

// A user disabled since /auth/completed is answered access_denied by redirect, and the event is the
// one /auth/completed writes for the same condition, so an administrator reading the audit log
// finds one event wherever it was caught (decision 17).
func TestHandleIssueGet_ADisabledUserIsAnsweredAccessDenied(t *testing.T) {
	for _, tc := range []struct {
		responseType string
		inFragment   bool
	}{
		{"code", false},
		{"token", true},
		{"id_token token", true},
	} {
		t.Run(tc.responseType, func(t *testing.T) {
			f := newRecheckFixture(t, tc.responseType, "")
			f.user.Enabled = false

			var order []string
			f.auditLogger.On("Log", mock.Anything, audit.EventUserDisabled, map[string]interface{}{
				"user_id": int64(123),
			}).Run(func(mock.Arguments) { order = append(order, "audit") }).Return().Once()
			f.ceremonyStore.On("ClearAuthContext", f.rr, f.req).
				Run(func(mock.Arguments) { order = append(order, "clear") }).Return(nil).Once()

			f.serve()

			require.Equal(t, http.StatusFound, f.rr.Code)
			params := answerParams(t, f.rr.Header().Get("Location"), tc.inFragment)
			assert.Equal(t, "access_denied", params.Get("error"))
			assert.Equal(t, "The user account is disabled.", params.Get("error_description"))
			assert.Equal(t, "test-state", params.Get("state"))
			assert.Equal(t, []string{"audit", "clear"}, order)
			f.assertNothingIssued(t)
			f.auditLogger.AssertExpectations(t)
		})
	}
}

// A credential the user has changed since the ceremony authenticated is not honoured: the ceremony
// restarts at level 1, exactly as one whose session is gone does, or is answered login_required
// when the request forbids UI (decision 17).
func TestHandleIssueGet_AStaleGenerationRestartsTheCeremony(t *testing.T) {
	for _, tc := range []struct {
		name         string
		responseType string
		inFragment   bool
	}{
		{"code", "code", false},
		{"implicit", "id_token token", true},
	} {
		t.Run(tc.name+", interactive, restarts at level 1 and writes nothing to the client", func(t *testing.T) {
			f := newRecheckFixture(t, tc.responseType, "")
			f.user.AuthStateGeneration = recheckGeneration + 1
			logs := logtest.CaptureSlog(t)

			var saved *ceremony.AuthContext
			f.ceremonyStore.On("SaveAuthContext", f.rr, f.req, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
				return ac.AuthState == ceremony.AuthStateRequiresLevel1
			})).Run(func(args mock.Arguments) { saved = args.Get(2).(*ceremony.AuthContext) }).Return(nil).Once()

			f.serve()

			require.Equal(t, http.StatusFound, f.rr.Code)
			assert.Equal(t, testCeremonyId, assertStepLocation(t, f.rr.Header().Get("Location"), "/auth/level1"))
			require.NotNil(t, saved)
			assert.Zero(t, saved.AuthStateGeneration, "the attempt is discarded with the restart")
			assert.Zero(t, saved.UserId, "whoever signs in next is not assumed to be this user")
			assert.Equal(t, "openid", saved.Scope, "the request survives the restart")
			f.assertNothingIssued(t)
			f.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
			f.ceremonyStore.AssertNotCalled(t, "ClearAuthContext", mock.Anything, mock.Anything)

			warning, ok := warningSaying(t, logs, "authentication generation has moved on")
			if ok {
				assert.EqualValues(t, 123, warning.Attrs["ceremony_user_id"])
			}
		})

		t.Run(tc.name+", silent, is answered login_required", func(t *testing.T) {
			f := newRecheckFixture(t, tc.responseType, "none")
			f.user.AuthStateGeneration = recheckGeneration + 1

			f.ceremonyStore.On("ClearAuthContext", f.rr, f.req).Return(nil).Once()

			f.serve()

			require.Equal(t, http.StatusFound, f.rr.Code)
			params := answerParams(t, f.rr.Header().Get("Location"), tc.inFragment)
			assert.Equal(t, "login_required", params.Get("error"))
			assert.Equal(t, "User authentication is required", params.Get("error_description"))
			assert.Equal(t, "test-state", params.Get("state"))
			f.assertNothingIssued(t)
			f.ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
			f.ceremonyStore.AssertExpectations(t)
		})
	}

	// The other direction: the token endpoint compares for equality, so a ceremony claiming a
	// generation the user has not reached is no more current than a stale one.
	t.Run("a ceremony ahead of the user's generation is refused as well", func(t *testing.T) {
		f := newRecheckFixture(t, "code", "")
		f.user.AuthStateGeneration = recheckGeneration - 1

		f.ceremonyStore.On("SaveAuthContext", f.rr, f.req, mock.Anything).Return(nil).Once()

		f.serve()

		assertStepLocation(t, f.rr.Header().Get("Location"), "/auth/level1")
		f.assertNothingIssued(t)
	})
}

// The implicit grant now signs inside a transaction that takes the session row first, so the
// session can be found gone at the signing as well as at the liveness read above it. The answer is
// the read's, written only after the issuer has returned (its rollback), and nothing is attested
// or cleared for tokens that were never signed (decision 16).
func TestHandleIssueGet_AnImplicitSessionEndedAtTheSigningIsAnsweredAsAGoneSession(t *testing.T) {
	t.Run("interactive, restarts at level 1", func(t *testing.T) {
		f := newRecheckFixture(t, "id_token token", "")

		var order []string
		f.implicitIssuer.On("IssueImplicitTx", mock.Anything, mock.Anything, mock.Anything, true, true).
			Run(func(mock.Arguments) { order = append(order, "issued") }).
			Return(nil, errs.WithStack(issuance.ErrIssuingSessionGone)).Once()
		f.ceremonyStore.On("SaveAuthContext", f.rr, f.req, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
			return ac.AuthState == ceremony.AuthStateRequiresLevel1
		})).Run(func(mock.Arguments) { order = append(order, "save") }).Return(nil).Once()

		f.serve()

		require.Equal(t, http.StatusFound, f.rr.Code)
		assert.Equal(t, testCeremonyId, assertStepLocation(t, f.rr.Header().Get("Location"), "/auth/level1"))
		assert.Equal(t, []string{"issued", "save"}, order, "the refusal writes the store only after the issuer has rolled back")
		f.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		f.ceremonyStore.AssertNotCalled(t, "ClearAuthContext", mock.Anything, mock.Anything)
		f.pageRenderer.AssertNotCalled(t, "InternalServerError", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("silent, is answered login_required in the fragment", func(t *testing.T) {
		f := newRecheckFixture(t, "token", "none")

		f.implicitIssuer.On("IssueImplicitTx", mock.Anything, mock.Anything, mock.Anything, true, false).
			Return(nil, errs.WithStack(issuance.ErrIssuingSessionGone)).Once()
		f.ceremonyStore.On("ClearAuthContext", f.rr, f.req).Return(nil).Once()

		f.serve()

		require.Equal(t, http.StatusFound, f.rr.Code)
		params := answerParams(t, f.rr.Header().Get("Location"), true)
		assert.Equal(t, "login_required", params.Get("error"))
		assert.Empty(t, params.Get("access_token"))
		f.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		f.ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
	})

	// A statement that did not run has not established that the session is gone, so answering it
	// as though it had would restart a ceremony whose session is alive.
	t.Run("any other failure is a 500, not a refusal", func(t *testing.T) {
		f := newRecheckFixture(t, "token", "")
		boom := errs.New("connection refused")

		f.implicitIssuer.On("IssueImplicitTx", mock.Anything, mock.Anything, mock.Anything, true, false).
			Return(nil, boom).Once()
		f.pageRenderer.On("InternalServerError", f.rr, f.req, mock.MatchedBy(func(err error) bool {
			return errors.Is(err, boom)
		})).Return().Once()

		f.serve()

		assert.Empty(t, f.rr.Header().Get("Location"))
		f.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		f.ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
		f.ceremonyStore.AssertNotCalled(t, "ClearAuthContext", mock.Anything, mock.Anything)
		f.pageRenderer.AssertExpectations(t)
	})
}

// An implicit ceremony now needs the session the code flow needs (decision 16): with no identifier
// in the request it is the gone shape and the issuer is never reached. This is the case the
// exemption used to serve.
func TestHandleIssueGet_AnImplicitCeremonyWithNoSessionIdentifierIsNotIssued(t *testing.T) {
	f := newRecheckFixtureFor(t, "id_token token", "", "")

	f.ceremonyStore.On("SaveAuthContext", f.rr, f.req, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
		return ac.AuthState == ceremony.AuthStateRequiresLevel1
	})).Return(nil).Once()

	f.serve()

	require.Equal(t, http.StatusFound, f.rr.Code)
	assertStepLocation(t, f.rr.Header().Get("Location"), "/auth/level1")
	f.assertNothingIssued(t)
}

// The issuer is handed the ceremony and the session the request resolved, and the attestation, the
// clear and the answer follow the issuer's return in that order: they attest to tokens that were
// signed and committed (decision 16).
func TestHandleIssueGet_TheImplicitIssuerIsHandedTheSessionAndAnswersAfterItsCommit(t *testing.T) {
	f := newRecheckFixture(t, "id_token token", "")
	f.authContext.ResponseMode = "fragment"

	var order []string
	var handed *issuance.ImplicitGrantInput
	f.implicitIssuer.On("IssueImplicitTx", mock.Anything, theseSettings(f.settings), mock.Anything, true, true).
		Run(func(args mock.Arguments) {
			order = append(order, "issued")
			handed = args.Get(2).(*issuance.ImplicitGrantInput)
		}).
		Return(&issuance.ImplicitGrantResponse{AccessToken: "the-token", IdToken: "the-id-token", TokenType: "Bearer",
			ExpiresIn: 60, Scope: "openid"}, nil).Once()
	f.auditLogger.On("Log", mock.Anything, audit.EventTokenIssuedImplicitResponse, mock.Anything).
		Run(func(mock.Arguments) { order = append(order, "audit") }).Return().Once()
	f.ceremonyStore.On("ClearAuthContext", f.rr, f.req).
		Run(func(mock.Arguments) { order = append(order, "clear") }).Return(nil).Once()

	f.serve()

	require.Equal(t, http.StatusFound, f.rr.Code)
	params := answerParams(t, f.rr.Header().Get("Location"), true)
	assert.Equal(t, "the-token", params.Get("access_token"))
	assert.Equal(t, "the-id-token", params.Get("id_token"))
	assert.Equal(t, []string{"issued", "audit", "clear"}, order)

	require.NotNil(t, handed)
	assert.Equal(t, liveSessionIdentifier, handed.SessionIdentifier,
		"the issuer takes the row of the session the request resolved, so handing it any other orders nothing")
	assert.Equal(t, int64(recheckGeneration), handed.AuthStateGeneration)
	assert.Equal(t, "test-nonce", handed.Nonce)
	assert.Equal(t, "openid", handed.Scope)
	assert.Same(t, f.client, handed.Client)
	assert.Same(t, f.user, handed.User)
}
