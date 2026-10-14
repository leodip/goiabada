package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// /auth/issue reads its settings at the route boundary before anything else, so a request reaching
// it without them answers the 500 page carrying reqctx.ErrNoSettings and reads nothing, not even its
// ceremony (#580 decision 5).
func TestMissingSettings_IssueAnswersBeforeReadingItsCeremony(t *testing.T) {
	pageRenderer := handlersmocks.NewPageRenderer(t)
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	database := datamocks.NewDatabase(t)
	codeIssuer := handlersmocks.NewCodeIssuer(t)
	implicitIssuer := handlersmocks.NewImplicitTokenIssuer(t)

	req := httptest.NewRequest(http.MethodGet, "/auth/issue?ceremony="+testCeremonyId, nil)
	rr := httptest.NewRecorder()
	pageRenderer.On("InternalServerError", rr, req, mock.MatchedBy(isErrNoSettings)).Return().Once()

	buildIssueGet(issueGetDeps{
		pageRenderer:        pageRenderer,
		ceremonyStore:       ceremonyStore,
		codeIssuer:          codeIssuer,
		implicitTokenIssuer: implicitIssuer,
		database:            database,
		auditLogger:         handlersmocks.NewAuditLogger(t),
		userSessionManager:  handlersmocks.NewUserSessionManager(t),
		permissionChecker:   handlersmocks.NewPermissionChecker(t),
	}).ServeHTTP(rr, req)

	pageRenderer.AssertExpectations(t)
	ceremonyStore.AssertNotCalled(t, "GetAuthContext", req)
	ceremonyStore.AssertNotCalled(t, "ClearAuthContext", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "GetClientByClientIdentifier", mock.Anything, mock.Anything, mock.Anything)
	codeIssuer.AssertNotCalled(t, "IssueAuthCodeTx", mock.Anything, mock.Anything)
	implicitIssuer.AssertNotCalled(t, "IssueImplicitTx", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// An implicit ceremony reaches /auth/issue with the auth time /auth/completed took from the session
// it bound to, and its tokens' auth_time is that instant (OIDC Core 1.0 section 2), never the clock
// read at signing.
func TestHandleIssueGet_TheImplicitTokensCarryTheCeremonysAuthTime(t *testing.T) {
	f := newRecheckFixture(t, "id_token token", "")
	authenticatedAt := time.Date(2026, 10, 14, 9, 30, 0, 0, time.UTC)
	f.authContext.AuthenticatedAt = &authenticatedAt

	var handed *issuance.ImplicitGrantInput
	f.implicitIssuer.On("IssueImplicitTx", mock.Anything, theseSettings(f.settings), mock.Anything, true, true).
		Run(func(args mock.Arguments) { handed = args.Get(2).(*issuance.ImplicitGrantInput) }).
		Return(&issuance.ImplicitGrantResponse{AccessToken: "the-token", IdToken: "the-id-token", TokenType: "Bearer",
			ExpiresIn: 60, Scope: "openid"}, nil).Once()
	f.auditLogger.On("Log", mock.Anything, audit.EventTokenIssuedImplicitResponse, mock.Anything).Return().Once()
	f.ceremonyStore.On("ClearAuthContext", f.rr, f.req, testCeremonyId).Return(nil).Once()

	f.serve()

	require.Equal(t, http.StatusFound, f.rr.Code)
	require.NotNil(t, handed)
	assert.Equal(t, time.Date(2026, 10, 14, 9, 30, 0, 0, time.UTC), handed.AuthenticatedAt)
}

// An implicit ceremony without an auth time is not one /auth/completed hands on, since it always
// sets one from the session it binds to. It is refused with a 500 and nothing is signed, attested or
// cleared: an auth_time is never invented for it (#580 decision 5).
func TestHandleIssueGet_AnImplicitCeremonyWithNoAuthTimeIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name            string
		authenticatedAt *time.Time
	}{
		{"none", nil},
		{"the zero instant", &time.Time{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRecheckFixture(t, "id_token token", "")
			f.authContext.AuthenticatedAt = tc.authenticatedAt
			f.pageRenderer.On("InternalServerError", f.rr, f.req, mock.Anything).Return().Once()

			f.serve()

			f.pageRenderer.AssertExpectations(t)
			f.assertNothingIssued(t)
			assert.Empty(t, f.rr.Header().Get("Location"))
			f.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
			f.ceremonyStore.AssertNotCalled(t, "ClearAuthContext", mock.Anything, mock.Anything, mock.Anything)
			f.ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// What was issued and cleared but cannot be written to the client, here a form_post with no
// form_post.html to render it through, answers 500 after the clear. The code or the tokens reach
// nobody.
func TestHandleIssueGet_AnAnswerThatCannotBeWrittenIs500(t *testing.T) {
	t.Run("a code", func(t *testing.T) {
		f := newRecheckFixture(t, "code", "")
		f.authContext.ResponseMode = "form_post"

		var order []string
		f.codeIssuer.On("IssueAuthCodeTx", mock.Anything, mock.Anything).
			Return(&record.Code{Id: 1, Code: "the-code", ClientId: 1, RedirectURI: f.authContext.RedirectURI}, nil).Once()
		f.auditLogger.On("Log", mock.Anything, audit.EventCreatedAuthCode, mock.Anything).Return().Once()
		f.ceremonyStore.On("ClearAuthContext", f.rr, f.req, testCeremonyId).
			Run(func(mock.Arguments) { order = append(order, "clear") }).Return(nil).Once()
		f.pageRenderer.On("InternalServerError", f.rr, f.req, mock.Anything).
			Run(func(mock.Arguments) { order = append(order, "500") }).Return().Once()

		f.serve()

		assert.Equal(t, []string{"clear", "500"}, order)
		assert.NotContains(t, f.rr.Body.String(), "the-code")
	})

	t.Run("implicit tokens", func(t *testing.T) {
		f := newRecheckFixture(t, "id_token token", "")
		f.authContext.ResponseMode = "form_post"
		authenticatedAt := time.Date(2026, 10, 14, 9, 30, 0, 0, time.UTC)
		f.authContext.AuthenticatedAt = &authenticatedAt

		var order []string
		f.implicitIssuer.On("IssueImplicitTx", mock.Anything, theseSettings(f.settings), mock.Anything, true, true).
			Return(&issuance.ImplicitGrantResponse{AccessToken: "the-token", IdToken: "the-id-token", TokenType: "Bearer",
				ExpiresIn: 60, Scope: "openid"}, nil).Once()
		f.auditLogger.On("Log", mock.Anything, audit.EventTokenIssuedImplicitResponse, mock.Anything).Return().Once()
		f.ceremonyStore.On("ClearAuthContext", f.rr, f.req, testCeremonyId).
			Run(func(mock.Arguments) { order = append(order, "clear") }).Return(nil).Once()
		f.pageRenderer.On("InternalServerError", f.rr, f.req, mock.Anything).
			Run(func(mock.Arguments) { order = append(order, "500") }).Return().Once()

		f.serve()

		assert.Equal(t, []string{"clear", "500"}, order)
		assert.NotContains(t, f.rr.Body.String(), "the-token")
	})
}
