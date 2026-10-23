package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The branches of the password step that no other case reaches: a client that cannot be read, a
// form that cannot be rendered, a lookup that fails, and a rotation or a save that fails other
// than by finding the ceremony replaced. Each answers the 500 page with the error it met and goes
// no further. The POST reads the client only for a form it shows again, so an accepted password
// reads none, and a client that cannot be read fails a refusal after what the refusal did.

// pwdStepMocks is one password step's doubles, strict, so a read or a write a case does not arm
// fails it.
type pwdStepMocks struct {
	pageRenderer  *handlersmocks.PageRenderer
	ceremonyStore *handlersmocks.CeremonyStore
	database      *datamocks.Database
	auditLogger   *handlersmocks.AuditLogger
}

func newPwdStepMocks(t *testing.T) pwdStepMocks {
	return pwdStepMocks{
		pageRenderer:  handlersmocks.NewPageRenderer(t),
		ceremonyStore: handlersmocks.NewCeremonyStore(t),
		database:      datamocks.NewDatabase(t),
		auditLogger:   handlersmocks.NewAuditLogger(t),
	}
}

func (m pwdStepMocks) get() http.HandlerFunc {
	return buildAuthPwdGet(authPwdGetDeps{pageRenderer: m.pageRenderer, ceremonyStore: m.ceremonyStore,
		database: m.database, auditLogger: m.auditLogger})
}

func (m pwdStepMocks) post() http.HandlerFunc {
	return buildAuthPwdPost(authPwdPostDeps{pageRenderer: m.pageRenderer, ceremonyStore: m.ceremonyStore,
		database: m.database, auditLogger: m.auditLogger})
}

// armPasswordCeremony stores a ceremony in level1_password for the client "test-client".
func (m pwdStepMocks) armPasswordCeremony() {
	m.ceremonyStore.On("GetAuthContext", mock.Anything).Return(&ceremony.AuthContext{
		AuthState:  ceremony.AuthStateLevel1Password,
		CeremonyId: testCeremonyId,
		ClientId:   "test-client",
	}, nil)
}

func (m pwdStepMocks) armClient() {
	m.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
		Return(&record.Client{ClientIdentifier: "test-client"}, nil)
}

func pwdGetRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/auth/pwd?ceremony="+testCeremonyId, nil)
	return req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{}))
}

func pwdPostRequest(email string, password string) *http.Request {
	form := url.Values{}
	form.Add(ceremony.IdField, testCeremonyId)
	form.Add("email", email)
	form.Add("password", password)
	req := httptest.NewRequest(http.MethodPost, "/auth/pwd", strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	return req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{}))
}

func isTheError(want error) interface{} {
	return mock.MatchedBy(func(err error) bool { return errors.Is(err, want) })
}

func isTheMessage(want string) interface{} {
	return mock.MatchedBy(func(err error) bool { return err != nil && err.Error() == want })
}

func TestHandleAuthPwdGet_AClientReadFailingAnswers500(t *testing.T) {
	m := newPwdStepMocks(t)
	req := pwdGetRequest()
	rr := httptest.NewRecorder()
	m.armPasswordCeremony()
	m.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
		Return(nil, assert.AnError).Once()
	m.pageRenderer.On("InternalServerError", rr, req, isTheError(assert.AnError)).Return().Once()

	m.get().ServeHTTP(rr, req)

	m.pageRenderer.AssertNotCalled(t, "RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything)
	m.database.AssertNotCalled(t, "ClientHasLogo", mock.Anything, mock.Anything, mock.Anything)
}

func TestHandleAuthPwdGet_AClientNotFoundAnswers500(t *testing.T) {
	m := newPwdStepMocks(t)
	req := pwdGetRequest()
	rr := httptest.NewRecorder()
	m.armPasswordCeremony()
	m.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
		Return(nil, nil).Once()
	m.pageRenderer.On("InternalServerError", rr, req, isTheMessage("client not found")).Return().Once()

	m.get().ServeHTTP(rr, req)

	m.pageRenderer.AssertNotCalled(t, "RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything)
}

func TestHandleAuthPwdGet_AFormThatCannotRenderAnswers500(t *testing.T) {
	m := newPwdStepMocks(t)
	req := pwdGetRequest()
	rr := httptest.NewRecorder()
	m.armPasswordCeremony()
	m.armClient()
	m.pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_pwd.html", mock.Anything).
		Return(assert.AnError).Once()
	m.pageRenderer.On("InternalServerError", rr, req, isTheError(assert.AnError)).Return().Once()

	m.get().ServeHTTP(rr, req)
}

// A wrong password whose form cannot be shown again, because the client cannot be read, answers 500
// once the guess is refused: it is charged to the rate limiter and audited first, as every wrong
// guess is, and nothing is rendered.
func TestHandleAuthPwdPost_AClientReadFailingOnARefusalAnswers500AfterTheCredentialCheck(t *testing.T) {
	m := newPwdStepMocks(t)
	failures := &credentialFailureSpy{}
	handler := buildAuthPwdPost(authPwdPostDeps{pageRenderer: m.pageRenderer, ceremonyStore: m.ceremonyStore,
		database: m.database, auditLogger: m.auditLogger, credentialFailures: failures})
	req := pwdPostRequest("test@example.com", "a-wrong-password")
	rr := httptest.NewRecorder()
	m.armPasswordCeremony()
	passwordHash, err := passwordhash.Hash("testpassword")
	require.NoError(t, err)
	m.database.On("GetUserByEmail", mock.Anything, mock.Anything, "test@example.com").Return(&record.User{
		Id: 1, Email: "test@example.com", PasswordHash: passwordHash, Enabled: true,
	}, nil).Once()
	m.auditLogger.On("Log", mock.Anything, audit.EventAuthFailedPwd, mock.Anything).Return().Once()
	m.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
		Return(nil, assert.AnError).Once()
	m.pageRenderer.On("InternalServerError", rr, req, isTheError(assert.AnError)).Return().Once()

	handler.ServeHTTP(rr, req)

	assert.Len(t, failures.requests, 1, "the refused guess is charged before the client is read")
	m.pageRenderer.AssertNotCalled(t, "RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything)
}

// A submission refused before any lookup whose client is gone answers 500 as the GET does, and still
// looks up no account.
func TestHandleAuthPwdPost_AClientNotFoundOnARefusalAnswers500(t *testing.T) {
	m := newPwdStepMocks(t)
	req := pwdPostRequest("", "testpassword")
	rr := httptest.NewRecorder()
	m.armPasswordCeremony()
	m.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
		Return(nil, nil).Once()
	m.pageRenderer.On("InternalServerError", rr, req, isTheMessage("client not found")).Return().Once()

	m.post().ServeHTTP(rr, req)

	m.database.AssertNotCalled(t, "GetUserByEmail", mock.Anything, mock.Anything, mock.Anything)
	m.pageRenderer.AssertNotCalled(t, "RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything)
}

// An accepted password shows no form, so it reads neither the client nor its logo: the step
// redirects to /auth/level1completed with the ceremony saved.
func TestHandleAuthPwdPost_AnAcceptedPasswordReadsNoClient(t *testing.T) {
	m := newPwdStepMocks(t)
	req := pwdPostRequest("test@example.com", "testpassword")
	rr := httptest.NewRecorder()
	m.armPasswordCeremony()
	m.armAcceptedPassword(t, "")
	m.ceremonyStore.On("RegenerateSession", rr, mock.Anything, testCeremonyId).Return(nil).Once()
	m.ceremonyStore.On("SaveAuthContext", rr, mock.Anything, mock.Anything).Return(nil).Once()

	m.post().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
	assert.Equal(t, "https://auth.test/auth/level1completed?ceremony="+testCeremonyId, rr.Header().Get("Location"))
	m.database.AssertNotCalled(t, "GetClientByClientIdentifier", mock.Anything, mock.Anything, mock.Anything)
	m.database.AssertNotCalled(t, "ClientHasLogo", mock.Anything, mock.Anything, mock.Anything)
}

// A failed lookup is a fault, not a refused credential: no audit record and no re-rendered form.
func TestHandleAuthPwdPost_ALookupFailingAnswers500(t *testing.T) {
	m := newPwdStepMocks(t)
	req := pwdPostRequest("test@example.com", "testpassword")
	rr := httptest.NewRecorder()
	m.armPasswordCeremony()
	m.database.On("GetUserByEmail", mock.Anything, mock.Anything, "test@example.com").
		Return(nil, assert.AnError).Once()
	m.pageRenderer.On("InternalServerError", rr, req, isTheError(assert.AnError)).Return().Once()

	m.post().ServeHTTP(rr, req)

	m.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	m.pageRenderer.AssertNotCalled(t, "RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything)
}

func TestHandleAuthPwdPost_ARefusalThatCannotRenderAnswers500(t *testing.T) {
	m := newPwdStepMocks(t)
	req := pwdPostRequest("", "testpassword")
	rr := httptest.NewRecorder()
	m.armPasswordCeremony()
	m.armClient()
	m.pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_pwd.html",
		mock.MatchedBy(func(data map[string]interface{}) bool { return data["error"] == "Email is required." })).
		Return(assert.AnError).Once()
	m.pageRenderer.On("InternalServerError", rr, req, isTheError(assert.AnError)).Return().Once()

	m.post().ServeHTTP(rr, req)
}

// armAcceptedPassword arms a user whose password "testpassword" is right, with the stored locale
// given, and the success audit record.
func (m pwdStepMocks) armAcceptedPassword(t *testing.T, locale string) {
	passwordHash, err := passwordhash.Hash("testpassword")
	require.NoError(t, err)
	m.database.On("GetUserByEmail", mock.Anything, mock.Anything, "test@example.com").Return(&record.User{
		Id: 1, Email: "test@example.com", PasswordHash: passwordHash, Enabled: true, Locale: locale,
	}, nil)
	m.auditLogger.On("Log", mock.Anything, audit.EventAuthSuccessPwd, map[string]interface{}{"user_id": int64(1)}).
		Return().Once()
}

// A rotation failing for any reason but a replaced ceremony is a 500, and the ceremony is not saved:
// the planted identifier must never name a password-completed row (#266).
func TestHandleAuthPwdPost_ARotationFailingAnswers500AndSavesNothing(t *testing.T) {
	m := newPwdStepMocks(t)
	req := pwdPostRequest("test@example.com", "testpassword")
	rr := httptest.NewRecorder()
	m.armPasswordCeremony()
	m.armAcceptedPassword(t, "")
	m.ceremonyStore.On("RegenerateSession", rr, mock.Anything, testCeremonyId).Return(assert.AnError).Once()
	m.pageRenderer.On("InternalServerError", rr, mock.Anything, isTheError(assert.AnError)).Return().Once()

	m.post().ServeHTTP(rr, req)

	m.ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
	assert.Empty(t, rr.Header().Get("Location"))
}

func TestHandleAuthPwdPost_ASaveFailingAnswers500(t *testing.T) {
	m := newPwdStepMocks(t)
	req := pwdPostRequest("test@example.com", "testpassword")
	rr := httptest.NewRecorder()
	m.armPasswordCeremony()
	m.armAcceptedPassword(t, "")
	m.ceremonyStore.On("RegenerateSession", rr, mock.Anything, testCeremonyId).Return(nil).Once()
	m.ceremonyStore.On("SaveAuthContext", rr, mock.Anything, mock.Anything).Return(assert.AnError).Once()
	m.pageRenderer.On("InternalServerError", rr, mock.Anything, isTheError(assert.AnError)).Return().Once()

	m.post().ServeHTTP(rr, req)

	assert.Empty(t, rr.Header().Get("Location"))
}

// Once the password is verified the step answers in the user's stored locale, and not before:
// "Authentication failed." stays in the request's, so its wording does not disclose that the
// address names an account. The request here carries no locale of its own, so it answers in
// English until the step switches.
func TestHandleAuthPwdPost_AnswersInTheUsersLocaleOnlyOnceThePasswordIsVerified(t *testing.T) {
	portuguese := i18n.WithLocale(httptest.NewRequest(http.MethodGet, "/", nil).Context(), true, "pt-BR")

	t.Run("a wrong password is refused in the request's locale", func(t *testing.T) {
		m := newPwdStepMocks(t)
		req := pwdPostRequest("test@example.com", "a-wrong-password")
		rr := httptest.NewRecorder()
		m.armPasswordCeremony()
		m.armClient()
		passwordHash, err := passwordhash.Hash("testpassword")
		require.NoError(t, err)
		m.database.On("GetUserByEmail", mock.Anything, mock.Anything, "test@example.com").Return(&record.User{
			Id: 1, Email: "test@example.com", PasswordHash: passwordHash, Enabled: true, Locale: "pt-BR",
		}, nil)
		m.auditLogger.On("Log", mock.Anything, audit.EventAuthFailedPwd, mock.Anything).Return().Once()
		m.pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_pwd.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				return data["error"] == "Authentication failed."
			})).Return(nil).Once()

		m.post().ServeHTTP(rr, req)
	})

	t.Run("a disabled account is answered in the user's locale", func(t *testing.T) {
		m := newPwdStepMocks(t)
		req := pwdPostRequest("test@example.com", "testpassword")
		rr := httptest.NewRecorder()
		m.armPasswordCeremony()
		m.armClient()
		passwordHash, err := passwordhash.Hash("testpassword")
		require.NoError(t, err)
		m.database.On("GetUserByEmail", mock.Anything, mock.Anything, "test@example.com").Return(&record.User{
			Id: 2, Email: "test@example.com", PasswordHash: passwordHash, Enabled: false, Locale: "pt-BR",
		}, nil)
		m.auditLogger.On("Log", mock.Anything, audit.EventUserDisabled, map[string]interface{}{"user_id": int64(2)}).
			Return().Once()
		m.pageRenderer.On("RenderTemplate", rr, mock.Anything, "/layouts/auth_layout.html", "/auth_pwd.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				return data["error"] == "Sua conta de usuário está desativada."
			})).Return(nil).Once()

		m.post().ServeHTTP(rr, req)

		m.ceremonyStore.AssertNotCalled(t, "RegenerateSession", mock.Anything, mock.Anything, mock.Anything)
		m.ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("a ceremony replaced after the password is answered in the user's locale", func(t *testing.T) {
		m := newPwdStepMocks(t)
		req := pwdPostRequest("test@example.com", "testpassword")
		rr := httptest.NewRecorder()
		m.armPasswordCeremony()
		m.armAcceptedPassword(t, "pt-BR")
		m.ceremonyStore.On("RegenerateSession", rr, mock.Anything, testCeremonyId).
			Return(ceremony.ErrCeremonyReplaced).Once()
		m.pageRenderer.On("RenderTemplate", rr, mock.Anything, "/layouts/no_menu_layout.html", "/auth_error.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				return data["_httpStatus"] == http.StatusBadRequest &&
					data["title"] == i18n.T(portuguese, "auth_error.ceremony_mismatch.title")
			})).Return(nil).Once()

		m.post().ServeHTTP(rr, req)

		require.NotEqual(t, i18n.T(portuguese, "auth_error.ceremony_mismatch.title"),
			i18n.T(req.Context(), "auth_error.ceremony_mismatch.title"),
			"the two locales must word the page differently for this case to tell them apart")
		m.ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
	})
}
