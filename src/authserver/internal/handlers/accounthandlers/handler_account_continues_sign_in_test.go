package accounthandlers

import (
	"bytes"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/afterresponse"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/emaillinks"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/usercreation"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/sessionstore"
)

// Registration carries on the sign-in that started it (#622 decision 9). When the browser holds the
// sign-in the password page's Create an account link named, still at the password step, registering
// without verification, or activating from the emailed link, records the password the user chose on
// that sign-in as the password page does: the browser session's identifier rotated, then the
// sign-in saved past the password, and the browser sent on to the sign-in's next step. Anywhere else
// the pages are today's, but for the activation reached from a sign-in the browser does not hold,
// which tells the person to go back to the application.

// signInsHeld is the browser's sign-ins as registration and activation see them: the ones it holds,
// by id, and the writes that carry one on, recorded in the order they were made.
type signInsHeld struct {
	held      map[string]*ceremony.AuthContext
	steps     []string
	rotatedId string
	rotatedTo int64
	saved     *ceremony.AuthContext
	rotateErr error
}

func (s *signInsHeld) HeldAuthContext(_ *http.Request, ceremonyId string) (*ceremony.AuthContext, error) {
	if len(s.held) == 0 {
		return nil, ceremony.ErrNoAuthContext
	}
	authContext, ok := s.held[ceremonyId]
	if !ok {
		return nil, errs.WithStack(ceremony.ErrCeremonyNotHeld)
	}
	held := *authContext
	return &held, nil
}

func (s *signInsHeld) RegenerateSession(_ http.ResponseWriter, _ *http.Request, ceremonyId string, userId int64) error {
	s.steps = append(s.steps, "rotate")
	s.rotatedId, s.rotatedTo = ceremonyId, userId
	return s.rotateErr
}

func (s *signInsHeld) SaveAuthContext(_ http.ResponseWriter, _ *http.Request, authContext *ceremony.AuthContext) error {
	s.steps = append(s.steps, "save")
	saved := *authContext
	s.saved = &saved
	return nil
}

// atThePasswordStep is a sign-in for an app, at the step whose page has the Create an account link.
func atThePasswordStep() *ceremony.AuthContext {
	return &ceremony.AuthContext{CeremonyId: aCeremonyId, ClientId: "shop", AuthState: ceremony.AuthStateLevel1Password}
}

// continuedSignIn is where a carried-on sign-in is sent: its next step after the password, naming it.
const continuedSignIn = testBaseURL + "/auth/level1completed?ceremony=" + aCeremonyId

const (
	newAccountEmail    = "newcomer@example.com"
	newAccountPassword = "Str0ngP4ss!"
	newAccountId       = int64(57)
)

// assertCarriedOn holds the sign-in to having been carried on for the new account: rotated, then
// saved past the password for it.
func assertCarriedOn(t *testing.T, signIns *signInsHeld) {
	t.Helper()
	assert.Equal(t, []string{"rotate", "save"}, signIns.steps, "the identifier is rotated before the save")
	assert.Equal(t, aCeremonyId, signIns.rotatedId)
	assert.Equal(t, newAccountId, signIns.rotatedTo)
	require.NotNil(t, signIns.saved)
	assert.Equal(t, ceremony.AuthStateLevel1PasswordCompleted, signIns.saved.AuthState)
	assert.Equal(t, newAccountId, signIns.saved.UserId)
	assert.True(t, signIns.saved.Level1AuthCompleted)
	assert.Equal(t, "shop", signIns.saved.ClientId)
}

// registerWithoutVerification is the register form submitted with a password, at the URL the
// Create an account link led to, query included.
func registerWithoutVerification(query string) *http.Request {
	form := url.Values{"email": {newAccountEmail}, "password": {newAccountPassword},
		"passwordConfirmation": {newAccountPassword}}
	req := httptest.NewRequest(http.MethodPost, "/account/register"+query, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req.WithContext(reqctx.WithSettings(req.Context(),
		&record.Settings{AppName: "TestApp", SelfRegistrationEnabled: true}))
}

// registration is HandleRegisterPost with the mocks a submission that creates an account calls.
type registration struct {
	pageRenderer *handlersmocks.PageRenderer
	auditLogger  *handlersmocks.AuditLogger
	audited      []string
	handler      http.HandlerFunc
}

func newRegistration(t *testing.T, signIns *signInsHeld) *registration {
	database := datamocks.NewDatabase(t)
	userCreator := accounthandlersmocks.NewUserCreator(t)
	emailValidator := accounthandlersmocks.NewEmailValidator(t)
	passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
	r := &registration{pageRenderer: handlersmocks.NewPageRenderer(t), auditLogger: handlersmocks.NewAuditLogger(t)}

	emailValidator.On("ValidateEmailAddress", newAccountEmail).Return(nil).Once()
	database.On("GetUserByEmail", mock.Anything, (*sql.Tx)(nil), newAccountEmail).Return(nil, nil).Once()
	database.On("GetPreRegistrationByEmail", mock.Anything, (*sql.Tx)(nil), newAccountEmail).Return(nil, nil).Once()
	passwordValidator.On("ValidatePassword", mock.Anything, newAccountPassword, mock.Anything).Return(nil).Once()
	userCreator.On("CreateUser", mock.Anything, mock.MatchedBy(func(input *usercreation.Input) bool {
		return input.Email == newAccountEmail
	})).Return(&record.User{Id: newAccountId, Email: newAccountEmail, Enabled: true}, nil).Once()
	r.auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		r.audited = append(r.audited, args.String(1))
	}).Return()

	r.handler = HandleRegisterPost(r.pageRenderer, signIns, legalDocumentsInEffect{}, database, userCreator,
		emailValidator, passwordValidator, accounthandlersmocks.NewEmailSender(t), r.auditLogger, &heldJobs{},
		testDataCipher, testBaseURL, testAdminConsoleBaseURL)
	return r
}

func TestHandleRegisterPost_CarriesOnTheSignInTheCreateAnAccountLinkNamed(t *testing.T) {
	signIns := &signInsHeld{held: map[string]*ceremony.AuthContext{aCeremonyId: atThePasswordStep()}}
	r := newRegistration(t, signIns)

	rr := httptest.NewRecorder()
	r.handler.ServeHTTP(rr, registerWithoutVerification("?ceremony="+aCeremonyId))

	assert.Equal(t, http.StatusSeeOther, rr.Code)
	assert.Equal(t, continuedSignIn, rr.Header().Get("Location"))
	assertCarriedOn(t, signIns)
	assert.Equal(t, []string{audit.EventCreatedUser, audit.EventAuthSuccessPwd}, r.audited)
	r.pageRenderer.AssertNotCalled(t, "RenderTemplate", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// Anywhere else registration answers today's "Account created" page, and writes nothing to the
// browser's sign-ins.
func TestHandleRegisterPost_KeepsTodaysPageWhenNoSignInIsCarriedOn(t *testing.T) {
	pastThePassword := atThePasswordStep()
	pastThePassword.AuthState = ceremony.AuthStateRequiresConsent

	tests := []struct {
		name      string
		query     string
		held      map[string]*ceremony.AuthContext
		rotateErr error
		wantSteps []string
	}{
		{"registration that did not start from a sign-in", "",
			map[string]*ceremony.AuthContext{aCeremonyId: atThePasswordStep()}, nil, nil},
		{"a sign-in the browser does not hold", "?ceremony=" + aCeremonyId,
			map[string]*ceremony.AuthContext{"another-sign-in-0123456789abcdef": atThePasswordStep()}, nil, nil},
		{"a browser holding no sign-in", "?ceremony=" + aCeremonyId, nil, nil, nil},
		{"a sign-in that has moved past the password step", "?ceremony=" + aCeremonyId,
			map[string]*ceremony.AuthContext{aCeremonyId: pastThePassword}, nil, nil},
		{"a sign-in the browser lost meanwhile", "?ceremony=" + aCeremonyId,
			map[string]*ceremony.AuthContext{aCeremonyId: atThePasswordStep()},
			errs.WithStack(ceremony.ErrCeremonyReplaced), []string{"rotate"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signIns := &signInsHeld{held: tc.held, rotateErr: tc.rotateErr}
			r := newRegistration(t, signIns)
			r.pageRenderer.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/auth_layout.html",
				"/account_register_success.html", mock.MatchedBy(func(data map[string]interface{}) bool {
					return data["email"] == newAccountEmail && data["adminConsoleBaseUrl"] == testAdminConsoleBaseURL
				})).Return(nil).Once()

			rr := httptest.NewRecorder()
			r.handler.ServeHTTP(rr, registerWithoutVerification(tc.query))

			assert.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, tc.wantSteps, signIns.steps)
			assert.Nil(t, signIns.saved, "the sign-in is not saved")
		})
	}
}

// With verification on, the emailed link carries the sign-in's id, so the activation can carry it
// on. The "check your email" page is bound with the address alone, as for every address.
func TestHandleRegisterPost_WithVerificationTheLinkCarriesTheSignIn(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		wantLink func(code string) string
	}{
		{"the sign-in the Create an account link named", "?ceremony=" + aCeremonyId, func(code string) string {
			return testBaseURL + "/account/activate?ceremony=" + aCeremonyId + "&code=" + code
		}},
		{"no sign-in", "", func(code string) string {
			return testBaseURL + "/account/activate?code=" + code
		}},
		{"a value that is not a sign-in's id", "?ceremony=" + url.QueryEscape("https://evil.example/"), func(code string) string {
			return testBaseURL + "/account/activate?code=" + code
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newRegisterHarness(t)
			req := registrationRequest(registerSomeoneEmail)
			req.URL.RawQuery = strings.TrimPrefix(tc.query, "?")
			rr := httptest.NewRecorder()

			h.expectLookups(registerSomeoneEmail, nil, nil)
			page := h.expectCheckEmailPage(rr, req)
			var created *record.PreRegistration
			h.database.On("CreatePreRegistration", mock.Anything, (*sql.Tx)(nil), mock.AnythingOfType("*record.PreRegistration")).
				Run(func(args mock.Arguments) { created = args.Get(2).(*record.PreRegistration) }).Return(nil).Once()
			h.auditLogger.On("Log", mock.Anything, audit.EventRequestedRegistration, mock.Anything).Return().Once()
			var mailBind map[string]interface{}
			h.pageRenderer.On("RenderTemplateToBuffer", mock.Anything, "/layouts/email_layout.html",
				"/emails/email_register_activate.html", mock.Anything).
				Run(func(args mock.Arguments) { mailBind = args.Get(3).(map[string]interface{}) }).
				Return(bytes.NewBufferString("activation mail"), nil).Once()
			h.emailSender.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).
				Return(nil).Once()

			h.handler.ServeHTTP(rr, req)
			assert.Equal(t, map[string]interface{}{"email": registerSomeoneEmail}, *page,
				"the page says nothing of the sign-in, the same for every address")
			h.jobs.runAll(t, afterresponse.ClassRegistration)

			require.NotNil(t, created)
			code, err := testDataCipher.Decrypt(created.VerificationCodeEncrypted)
			require.NoError(t, err)
			assert.Equal(t, tc.wantLink(code), mailBind["link"])
		})
	}
}

// The link's first hop keeps the sign-in's id on the clean URL it redirects to, where the form posts,
// and drops the code; a value that is not an id is not carried.
func TestHandleActivateGet_TheLinkFollowedKeepsTheSignIn(t *testing.T) {
	const code = "the-emitted-code"
	tests := []struct {
		name         string
		ceremony     string
		wantLocation string
	}{
		{"a sign-in's id", aCeremonyId, emaillinks.AccountActivatePath + "?ceremony=" + aCeremonyId},
		{"a value that is not one", "not-an-id", emaillinks.AccountActivatePath},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			preReg, codeHash := preRegistrationWithCode(t, 7, activateTestEmail, code, time.Now().UTC().Add(-time.Minute))
			database.On("GetPreRegistrationByVerificationCodeHash", mock.Anything, (*sql.Tx)(nil), codeHash).Return(preReg, nil).Once()

			handler := HandleActivateGet(handlersmocks.NewPageRenderer(t), newMarkerTestStore(), database,
				handlersmocks.NewAuditLogger(t), testDataCipher)
			target := emaillinks.AccountActivatePath + "?" + url.Values{"code": {code}, "ceremony": {tc.ceremony}}.Encode()
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, withSelfRegistration(httptest.NewRequest(http.MethodGet, target, nil), true))

			require.Equal(t, http.StatusSeeOther, rr.Code)
			assert.Equal(t, tc.wantLocation, rr.Header().Get("Location"))
		})
	}
}

// postActivationTo is the choose-password form submitted with the marker the first hop left, to the
// clean URL it redirected to, query included.
func postActivationTo(t *testing.T, store *sessionstore.ConditionalStore, query string, id int64,
	codeHash string) *http.Request {
	t.Helper()
	marked := postActivationWithMarker(t, store, newAccountPassword, newAccountPassword, id, codeHash)
	if err := marked.ParseForm(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, emaillinks.AccountActivatePath+query,
		strings.NewReader(marked.PostForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range marked.Cookies() {
		req.AddCookie(c)
	}
	return req.WithContext(reqctx.WithSettings(req.Context(), activationSettings))
}

// activation is HandleActivatePost with the mocks a submission that creates the account calls.
type activation struct {
	pageRenderer *handlersmocks.PageRenderer
	store        *sessionstore.ConditionalStore
	codeHash     string
	audited      []string
	handler      http.HandlerFunc
}

func newActivation(t *testing.T, signIns *signInsHeld) *activation {
	const code = "the-emitted-code"
	database := datamocks.NewDatabase(t)
	userCreator := accounthandlersmocks.NewTransactionalUserCreator(t)
	passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	a := &activation{pageRenderer: handlersmocks.NewPageRenderer(t), store: newMarkerTestStore()}

	preReg, codeHash := preRegistrationWithCode(t, 7, activateTestEmail, code, time.Now().UTC())
	a.codeHash = codeHash
	database.On("GetPreRegistrationByVerificationCodeHash", mock.Anything, (*sql.Tx)(nil), codeHash).Return(preReg, nil).Once()
	database.On("GetUserByEmail", mock.Anything, (*sql.Tx)(nil), activateTestEmail).Return(nil, nil).Once()
	passwordValidator.On("ValidatePassword", mock.Anything, newAccountPassword, mock.Anything).Return(nil).Once()
	datamocks.ExpectRunInTransaction(database, activationTx, func(string) {})
	database.On("DeletePreRegistrationHoldingCode", mock.Anything, activationTx, int64(7), codeHash).Return(true, nil).Once()
	userCreator.On("CreateUserInTransaction", mock.Anything, activationTx, mock.Anything).
		Return(&record.User{Id: newAccountId, Email: activateTestEmail, Enabled: true, EmailVerified: true}, nil).Once()
	auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		a.audited = append(a.audited, args.String(1))
	}).Return()

	a.handler = HandleActivatePost(a.pageRenderer, a.store, signIns, database, userCreator, passwordValidator,
		auditLogger, testBaseURL, testAdminConsoleBaseURL)
	return a
}

func TestHandleActivatePost_CarriesOnTheSignInTheLinkNamed(t *testing.T) {
	signIns := &signInsHeld{held: map[string]*ceremony.AuthContext{aCeremonyId: atThePasswordStep()}}
	a := newActivation(t, signIns)

	rr := httptest.NewRecorder()
	sent := postActivationTo(t, a.store, "?ceremony="+aCeremonyId, 7, a.codeHash)
	a.handler.ServeHTTP(rr, sent)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
	assert.Equal(t, continuedSignIn, rr.Header().Get("Location"))
	assertCarriedOn(t, signIns)
	assert.Equal(t, []string{audit.EventCreatedUser, audit.EventActivatedAccount, audit.EventAuthSuccessPwd}, a.audited)
	a.pageRenderer.AssertNotCalled(t, "RenderTemplate", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)

	_, rejection, err := emaillinks.GetLinkMarker(a.store, nextBrowserRequest(t, sent, rr, activationCleanGetRequest),
		emaillinks.LinkMarkerFlowAccountActivate)
	require.NoError(t, err)
	assert.Equal(t, emaillinks.LinkMarkerMissing, rejection, "the link's marker is cleared all the same")
}

// The account is activated whatever becomes of the sign-in. Reached from one the browser does not
// hold, the page tells the person to go back to the application; reached from none, it is today's.
func TestHandleActivatePost_ActivatesWhereTheSignInIsNotHeld(t *testing.T) {
	pastThePassword := atThePasswordStep()
	pastThePassword.AuthState = ceremony.AuthStateRequiresConsent

	tests := []struct {
		name            string
		query           string
		held            map[string]*ceremony.AuthContext
		rotateErr       error
		wantReturnToApp bool
	}{
		{"a link opened in another browser", "?ceremony=" + aCeremonyId, nil, nil, true},
		{"a sign-in this browser no longer holds", "?ceremony=" + aCeremonyId,
			map[string]*ceremony.AuthContext{"another-sign-in-0123456789abcdef": atThePasswordStep()}, nil, true},
		{"a sign-in that has moved past the password step", "?ceremony=" + aCeremonyId,
			map[string]*ceremony.AuthContext{aCeremonyId: pastThePassword}, nil, true},
		{"a sign-in the browser lost meanwhile", "?ceremony=" + aCeremonyId,
			map[string]*ceremony.AuthContext{aCeremonyId: atThePasswordStep()},
			errs.WithStack(ceremony.ErrCeremonyReplaced), true},
		{"registration that did not start from a sign-in", "",
			map[string]*ceremony.AuthContext{aCeremonyId: atThePasswordStep()}, nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signIns := &signInsHeld{held: tc.held, rotateErr: tc.rotateErr}
			a := newActivation(t, signIns)
			var bound map[string]interface{}
			a.pageRenderer.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/auth_layout.html",
				"/account_register_activation_result.html", mock.Anything).
				Run(func(args mock.Arguments) { bound = args.Get(4).(map[string]interface{}) }).Return(nil).Once()

			rr := httptest.NewRecorder()
			a.handler.ServeHTTP(rr, postActivationTo(t, a.store, tc.query, 7, a.codeHash))

			assert.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, map[string]interface{}{
				"email":               activateTestEmail,
				"adminConsoleBaseUrl": testAdminConsoleBaseURL,
				"returnToApp":         tc.wantReturnToApp,
			}, bound)
			assert.Contains(t, a.audited, audit.EventActivatedAccount, "the account is activated")
			assert.Nil(t, signIns.saved, "the sign-in is not saved")
		})
	}
}
