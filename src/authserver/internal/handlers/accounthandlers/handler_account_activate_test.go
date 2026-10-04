package accounthandlers

import (
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

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/emaillinks"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/usercreation"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/sessionstore"
)

// The activation flow's state machine, at seam 3.
//
// Every case here drives a URL the handler itself would produce: a first hop carrying only
// ?code=, or a clean hop carrying no query at all. That is the whole change (#112): the link
// used to carry ?email= too, and form-urlencoded query parsing turned a '+' in the address
// into a space, so the pre-registration was never found.

// withSelfRegistration attaches the settings middleware.Settings would have, with self-registration
// on or off. The handler refuses both hops while it is off (#425 decision 6).
func withSelfRegistration(req *http.Request, enabled bool) *http.Request {
	return req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{SelfRegistrationEnabled: enabled}))
}

// activationLinkFollowedRequest is the emailed link being followed: the code, and nothing else.
func activationLinkFollowedRequest(code string) *http.Request {
	target := emaillinks.AccountActivatePath
	if code != "" {
		target += "?" + url.Values{"code": {code}}.Encode()
	}
	return withSelfRegistration(httptest.NewRequest("GET", target, nil), true)
}

// activationCleanGetRequest is where the first hop's 303 lands: the same path, no query at all.
func activationCleanGetRequest() *http.Request {
	return withSelfRegistration(httptest.NewRequest("GET", emaillinks.AccountActivatePath, nil), true)
}

// preRegistrationWithCode builds a pending registration holding an outstanding activation
// code, along with the hash the link's code resolves to.
func preRegistrationWithCode(t *testing.T, id int64, email, code string, issuedAt time.Time) (*record.PreRegistration, string) {
	t.Helper()

	encrypted, err := testDataCipher.Encrypt(code)
	require.NoError(t, err)
	codeHash := hashutil.HashString(code)

	return &record.PreRegistration{
		Id:                        id,
		Email:                     email,
		VerificationCodeEncrypted: encrypted,
		VerificationCodeHash:      codeHash,
		VerificationCodeIssuedAt:  sql.NullTime{Time: issuedAt, Valid: true},
	}, codeHash
}

// expectRenderedLinkExpired matches the one response every link-attributable failure on a GET
// must produce: the activation result page in its "register again" state, at the template's own
// 200 (no _httpStatus), since mail scanners treat a 4xx as a broken link. A single matcher
// everywhere is deliberate, since these paths differing would tell a caller which of them
// happened.
func expectRenderedLinkExpired(pageRenderer *handlersmocks.PageRenderer) {
	expectRenderedLinkExpiredAt(pageRenderer, 0)
}

// expectRenderedLinkExpiredAt is the same page at a given status: 0 for the template's own 200,
// which every GET answers, and 400 for the POST, where a submission was refused, as the reset
// form's POST answers its refusals.
func expectRenderedLinkExpiredAt(pageRenderer *handlersmocks.PageRenderer, wantStatus int) {
	pageRenderer.On("RenderTemplate",
		mock.Anything,
		mock.Anything,
		"/layouts/auth_layout.html",
		"/account_register_activation_result.html",
		mock.MatchedBy(func(data map[string]interface{}) bool {
			flag, ok := data["linkHasExpired"].(bool)
			status, statusSet := data["_httpStatus"]
			if wantStatus == 0 {
				return ok && flag && !statusSet
			}
			return ok && flag && statusSet && status == wantStatus
		}),
	).Return(nil).Once()
}

// expectAuditFailedActivationCode requires exactly one audit entry for a refused link, carrying
// the reason the identical page withholds from the caller (#425 decision 5), in the shape the
// reset flow's entry has: the client IP always, no address anywhere, and preRegistrationId only on
// the branches where the lookup resolved a row the code matched. Pass 0 to require the key is
// ABSENT rather than zero, since a payload naming row 0 asserts a row that does not exist (#435).
func expectAuditFailedActivationCode(auditLogger *handlersmocks.AuditLogger, wantReason string,
	wantPreRegistrationId int64) {

	auditLogger.On("Log", mock.Anything, audit.EventFailedAccountActivationCode,
		mock.MatchedBy(func(details map[string]interface{}) bool {
			if details["reason"] != wantReason || details["ip"] != testClientIP {
				return false
			}
			if _, present := details["email"]; present {
				return false
			}
			id, present := details["preRegistrationId"]
			if wantPreRegistrationId == 0 {
				return !present
			}
			return present && id == wantPreRegistrationId
		}),
	).Return().Once()
}

// assertRefusalNotLogged holds a refusal to its audit entry alone. It wrote a Warn record until
// #435, which reached the console and not the audit log an administrator reads; reset has no
// record beside its entry, and now neither does activation.
func assertRefusalNotLogged(t *testing.T, logs *logtest.SlogCapture) {
	t.Helper()
	assert.Empty(t, logs.Records(), "a refused link is audited, not logged: %s", logs.Text())
}

// The '+' address is the class #112 reports as broken, and it is used throughout so that a
// regression putting the address back into the link cannot pass these tests.
const activateTestEmail = "user+tag@example.com"

// =============================================================================
// The first hop: the emailed link, carrying the code and nothing else.
// =============================================================================

func TestHandleActivateGet_LinkFollowed(t *testing.T) {
	const code = "the-emitted-code"

	t.Run("a valid code marks the session and redirects to a clean URL", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		store := newMarkerTestStore()

		preReg, codeHash := preRegistrationWithCode(t, 7, activateTestEmail, code, time.Now().UTC().Add(-time.Minute))
		database.On("GetPreRegistrationByVerificationCodeHash", mock.Anything, (*sql.Tx)(nil), codeHash).Return(preReg, nil).Once()

		handler := HandleActivateGet(pageRenderer, store, database, auditLogger, testDataCipher)
		rr := httptest.NewRecorder()
		sent := activationLinkFollowedRequest(code)
		handler.ServeHTTP(rr, sent)

		require.Equal(t, http.StatusSeeOther, rr.Code)

		location, err := url.Parse(rr.Header().Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, emaillinks.AccountActivatePath, location.Path)
		assert.Empty(t, location.RawQuery,
			"the redirect target must carry no query, so the code cannot persist in history or a Referer")

		// The row is NOT consumed: a link previewer prefetching the URL must leave the code
		// usable (#112 decision 7). No account can be created on this hop, or on the clean GET
		// after it: HandleActivateGet takes no UserCreator (#207 decision 1).
		database.AssertNotCalled(t, "DeletePreRegistration", mock.Anything, mock.Anything, mock.Anything)

		marker, rejection, err := emaillinks.GetLinkMarker(store, nextBrowserRequest(t, sent, rr, activationCleanGetRequest),
			emaillinks.LinkMarkerFlowAccountActivate)
		require.NoError(t, err)
		require.Empty(t, rejection)
		require.NotNil(t, marker)
		assert.Equal(t, codeHash, marker.CodeHash,
			"the marker must name the code hash, which is what stops it outliving the activation")
		assert.Equal(t, int64(7), marker.Id)

		database.AssertExpectations(t)
	})

	// A consumed code is the same case: the activation deletes the row, so a link clicked twice
	// resolves to nothing. It used to answer the 500 page with an error-level stack (#425).
	t.Run("a code matching no row is refused", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		store := newMarkerTestStore()
		logs := logtest.CaptureSlog(t)

		codeHash := hashutil.HashString(code)
		database.On("GetPreRegistrationByVerificationCodeHash", mock.Anything, (*sql.Tx)(nil), codeHash).Return(nil, nil).Once()
		expectRenderedLinkExpired(pageRenderer)
		expectAuditFailedActivationCode(auditLogger, "unknown_code", 0)

		handler := HandleActivateGet(pageRenderer, store, database, auditLogger, testDataCipher)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, activationLinkFollowedRequest(code))

		assert.Equal(t, http.StatusOK, rr.Code)
		assertRefusalNotLogged(t, logs)
		database.AssertExpectations(t)
		pageRenderer.AssertExpectations(t)
	})

	t.Run("a hash hit whose stored code does not match is refused", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		store := newMarkerTestStore()
		logs := logtest.CaptureSlog(t)

		// Reachable only through a SHA-256 collision, and asserted so the comparison behind
		// the index stays load-bearing rather than decorative.
		preReg, _ := preRegistrationWithCode(t, 7, activateTestEmail, "a-different-code", time.Now().UTC())
		codeHash := hashutil.HashString(code)
		database.On("GetPreRegistrationByVerificationCodeHash", mock.Anything, (*sql.Tx)(nil), codeHash).Return(preReg, nil).Once()
		expectRenderedLinkExpired(pageRenderer)
		// No preRegistrationId: the row matched a hash the supplied code does not reproduce, so
		// nothing about it is established as the subject of the request.
		expectAuditFailedActivationCode(auditLogger, "unknown_code", 0)

		handler := HandleActivateGet(pageRenderer, store, database, auditLogger, testDataCipher)
		rr := httptest.NewRecorder()
		sent := activationLinkFollowedRequest(code)
		handler.ServeHTTP(rr, sent)

		assert.Equal(t, http.StatusOK, rr.Code)
		assertRefusalNotLogged(t, logs)

		_, rejection, err := emaillinks.GetLinkMarker(store, nextBrowserRequest(t, sent, rr, activationCleanGetRequest),
			emaillinks.LinkMarkerFlowAccountActivate)
		require.NoError(t, err)
		assert.Equal(t, emaillinks.LinkMarkerMissing, rejection,
			"a refused code must not leave a usable marker behind")

		database.AssertExpectations(t)
		pageRenderer.AssertExpectations(t)
	})

	// A server fault is not a refusal: a stored code that will not decrypt keeps the 500 page and
	// its stack, and writes no refusal entry that would file it under a user's old link. The
	// strict audit mock has no expectation, so an entry fails the case.
	t.Run("a stored code that will not decrypt stays a server error", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		store := newMarkerTestStore()
		logs := logtest.CaptureSlog(t)

		preReg, codeHash := preRegistrationWithCode(t, 7, activateTestEmail, code, time.Now().UTC())
		preReg.VerificationCodeEncrypted = []byte("not ciphertext")
		database.On("GetPreRegistrationByVerificationCodeHash", mock.Anything, (*sql.Tx)(nil), codeHash).Return(preReg, nil).Once()
		pageRenderer.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "unable to decrypt verification code")
		})).Once()

		handler := HandleActivateGet(pageRenderer, store, database, auditLogger, testDataCipher)
		handler.ServeHTTP(httptest.NewRecorder(), activationLinkFollowedRequest(code))

		assert.Empty(t, logs.Records(), "a server fault must not be logged as a refused link")
		database.AssertExpectations(t)
		pageRenderer.AssertExpectations(t)
	})

	// The activation half of the same defect: the clean hop reads the marker alone, so two
	// interleaved first hops used to make the redirect already in flight activate the other
	// registration. First writer wins instead (#112 decision 13).
	t.Run("a second link followed while one is in flight is refused", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		store := newMarkerTestStore()

		// The second link is valid on its own: it is refused for the marker it would have
		// replaced, not for anything wrong with it.
		preReg, codeHash := preRegistrationWithCode(t, 99, "second@example.com", code, time.Now().UTC().Add(-time.Minute))
		database.On("GetPreRegistrationByVerificationCodeHash", mock.Anything, (*sql.Tx)(nil), codeHash).Return(preReg, nil).Once()
		expectRenderedLinkExpired(pageRenderer)
		// This link's pre-registration, which resolved; the one holding the live marker is not named.
		expectAuditFailedActivationCode(auditLogger, "continuation_in_flight", 99)

		sent := withMarker(t, store, activationLinkFollowedRequest(code),
			emaillinks.LinkMarkerFlowAccountActivate, 7, "the-first-hash")
		logs := logtest.CaptureSlog(t)

		handler := HandleActivateGet(pageRenderer, store, database, auditLogger, testDataCipher)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, sent)

		assert.NotEqual(t, http.StatusSeeOther, rr.Code, "a refused second link must not redirect")
		assertRefusalNotLogged(t, logs)
		database.AssertNotCalled(t, "DeletePreRegistration", mock.Anything, mock.Anything, mock.Anything)

		// The first continuation survives, so the redirect already in flight still activates
		// the registration whose link produced it.
		marker, rejection, err := emaillinks.GetLinkMarker(store, nextBrowserRequest(t, sent, rr, activationCleanGetRequest),
			emaillinks.LinkMarkerFlowAccountActivate)
		require.NoError(t, err)
		require.Empty(t, rejection)
		require.NotNil(t, marker)
		assert.Equal(t, "the-first-hash", marker.CodeHash)
		assert.Equal(t, int64(7), marker.Id)

		database.AssertExpectations(t)
		pageRenderer.AssertExpectations(t)
	})

	// The same refusal against a live marker of the OTHER flow. Scoping the rule to one flow
	// left a bridge: one cross-flow replacement is harmless because every consuming step
	// refuses a wrong-flow marker, but a second replacement puts the slot back into the flow
	// it started in, which is the retarget in three navigations rather than one
	// (#112 decision 14).
	t.Run("a link followed while a reset continuation is in flight is refused", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		store := newMarkerTestStore()

		preReg, codeHash := preRegistrationWithCode(t, 99, "second@example.com", code, time.Now().UTC().Add(-time.Minute))
		database.On("GetPreRegistrationByVerificationCodeHash", mock.Anything, (*sql.Tx)(nil), codeHash).Return(preReg, nil).Once()
		expectRenderedLinkExpired(pageRenderer)
		expectAuditFailedActivationCode(auditLogger, "continuation_in_flight", 99)

		sent := withMarker(t, store, activationLinkFollowedRequest(code),
			emaillinks.LinkMarkerFlowResetPassword, 42, "the-reset-hash")
		logs := logtest.CaptureSlog(t)

		handler := HandleActivateGet(pageRenderer, store, database, auditLogger, testDataCipher)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, sent)

		assert.NotEqual(t, http.StatusSeeOther, rr.Code, "a refused link must not redirect")
		assertRefusalNotLogged(t, logs)
		database.AssertNotCalled(t, "DeletePreRegistration", mock.Anything, mock.Anything, mock.Anything)

		marker, rejection, err := emaillinks.GetLinkMarker(store, nextBrowserRequest(t, sent, rr, activationCleanGetRequest),
			emaillinks.LinkMarkerFlowResetPassword)
		require.NoError(t, err)
		require.Empty(t, rejection)
		require.NotNil(t, marker)
		assert.Equal(t, "the-reset-hash", marker.CodeHash,
			"the reset continuation must still own the session")

		database.AssertExpectations(t)
		pageRenderer.AssertExpectations(t)
	})

	t.Run("an expired code deletes the pending registration and asks for another", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		store := newMarkerTestStore()

		preReg, codeHash := preRegistrationWithCode(t, 7, activateTestEmail, code, time.Now().UTC().Add(-6*time.Minute))
		database.On("GetPreRegistrationByVerificationCodeHash", mock.Anything, (*sql.Tx)(nil), codeHash).Return(preReg, nil).Once()
		database.On("DeletePreRegistration", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(nil).Once()
		expectRenderedLinkExpired(pageRenderer)
		expectAuditFailedActivationCode(auditLogger, "code_expired", 7)
		logs := logtest.CaptureSlog(t)

		handler := HandleActivateGet(pageRenderer, store, database, auditLogger, testDataCipher)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, activationLinkFollowedRequest(code))

		assert.Equal(t, http.StatusOK, rr.Code)
		assertRefusalNotLogged(t, logs)
		database.AssertExpectations(t)
		pageRenderer.AssertExpectations(t)
	})

	t.Run("the code's lifetime boundary", func(t *testing.T) {
		// Both sides of the 5-minute window, so the constant cannot be widened or narrowed
		// without a test noticing.
		for _, tc := range []struct {
			name     string
			issuedAt time.Time
			expired  bool
		}{
			{"just inside the window", time.Now().UTC().Add(-emaillinks.ActivationCodeLifetime + 2*time.Second), false},
			{"just outside the window", time.Now().UTC().Add(-emaillinks.ActivationCodeLifetime - 2*time.Second), true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				pageRenderer := handlersmocks.NewPageRenderer(t)
				database := datamocks.NewDatabase(t)
				auditLogger := handlersmocks.NewAuditLogger(t)
				store := newMarkerTestStore()

				preReg, codeHash := preRegistrationWithCode(t, 7, activateTestEmail, code, tc.issuedAt)
				database.On("GetPreRegistrationByVerificationCodeHash", mock.Anything, (*sql.Tx)(nil), codeHash).Return(preReg, nil).Once()
				if tc.expired {
					database.On("DeletePreRegistration", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(nil).Once()
					expectRenderedLinkExpired(pageRenderer)
					expectAuditFailedActivationCode(auditLogger, "code_expired", 7)
				}

				handler := HandleActivateGet(pageRenderer, store, database, auditLogger, testDataCipher)
				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, activationLinkFollowedRequest(code))

				if tc.expired {
					assert.NotEqual(t, http.StatusSeeOther, rr.Code)
				} else {
					assert.Equal(t, http.StatusSeeOther, rr.Code)
				}

				database.AssertExpectations(t)
				pageRenderer.AssertExpectations(t)
			})
		}
	})
}

// =============================================================================
// The clean hop: no query at all, the marker alone.
// =============================================================================

func TestHandleActivateGet_Clean(t *testing.T) {
	const code = "the-emitted-code"

	// The clean GET renders the form and creates nothing: a scanner or previewer that fetches the
	// link, and follows its redirect, has no account to show for it, since only the form's POST
	// creates one (#207 decision 1). The handler takes no UserCreator at all, so this case pins
	// what it renders and that the pending registration and the marker both survive for the POST.
	t.Run("the marker renders the choose-password form and creates nothing", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		store := newMarkerTestStore()

		preReg, codeHash := preRegistrationWithCode(t, 7, activateTestEmail, code, time.Now().UTC())
		database.On("GetPreRegistrationByVerificationCodeHash", mock.Anything, (*sql.Tx)(nil), codeHash).Return(preReg, nil).Once()
		database.On("GetUserByEmail", mock.Anything, (*sql.Tx)(nil), activateTestEmail).Return(nil, nil).Once()

		sent := withMarker(t, store, activationCleanGetRequest(), emaillinks.LinkMarkerFlowAccountActivate, 7, codeHash)
		marker, rejection, err := emaillinks.GetLinkMarker(store, sent, emaillinks.LinkMarkerFlowAccountActivate)
		require.NoError(t, err)
		require.Empty(t, rejection)

		var rendered map[string]interface{}
		pageRenderer.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/auth_layout.html",
			"/account_activate_password.html", mock.Anything).
			Run(func(args mock.Arguments) { rendered = args.Get(4).(map[string]interface{}) }).
			Return(nil).Once()

		handler := HandleActivateGet(pageRenderer, store, database, auditLogger, testDataCipher)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, sent)

		require.NotNil(t, rendered)
		assert.Equal(t, marker.ContinuationId, rendered["continuationId"],
			"the form must carry the continuation id of the marker that rendered it")
		assert.Equal(t, activateTestEmail, rendered["email"])
		assert.NotContains(t, rendered, "error")

		database.AssertNotCalled(t, "DeletePreRegistration", mock.Anything, mock.Anything, mock.Anything)
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)

		_, rejection, err = emaillinks.GetLinkMarker(store, nextBrowserRequest(t, sent, rr, activationCleanGetRequest),
			emaillinks.LinkMarkerFlowAccountActivate)
		require.NoError(t, err)
		assert.Empty(t, rejection, "rendering the form must leave the marker for the POST")

		database.AssertExpectations(t)
		pageRenderer.AssertExpectations(t)
	})

	// The address gained an account between registration and this link: an administrator created
	// it, or registration without verification ran for it. Refused with the flow's one page at
	// 200, audited as address_taken naming the pending registration, which is deleted because it
	// can never complete (#207 decision 10). It used to reach the user insert and answer the 500
	// page.
	t.Run("an address that already has an account is refused and its pending registration deleted", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		store := newMarkerTestStore()
		logs := logtest.CaptureSlog(t)

		preReg, codeHash := preRegistrationWithCode(t, 7, activateTestEmail, code, time.Now().UTC())
		database.On("GetPreRegistrationByVerificationCodeHash", mock.Anything, (*sql.Tx)(nil), codeHash).Return(preReg, nil).Once()
		database.On("GetUserByEmail", mock.Anything, (*sql.Tx)(nil), activateTestEmail).
			Return(&record.User{Id: 3, Email: activateTestEmail}, nil).Once()
		database.On("DeletePreRegistration", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(nil).Once()
		expectRenderedLinkExpired(pageRenderer)
		expectAuditFailedActivationCode(auditLogger, "address_taken", 7)

		handler := HandleActivateGet(pageRenderer, store, database, auditLogger, testDataCipher)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, withMarker(t, store, activationCleanGetRequest(), emaillinks.LinkMarkerFlowAccountActivate, 7, codeHash))

		assert.Equal(t, http.StatusOK, rr.Code)
		assertRefusalNotLogged(t, logs)
		database.AssertExpectations(t)
		pageRenderer.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("every marker-attributable refusal renders the same page and creates nothing", func(t *testing.T) {
		codeHash := hashutil.HashString(code)

		for _, tc := range []struct {
			name    string
			request func(t *testing.T, store sessionstore.Store) *http.Request
			// resolves is true when the handler gets far enough to look the hash up.
			resolves bool
			// reason is what the refusal entry names, the one place the rows differ.
			reason string
		}{
			{
				name: "no marker at all, a bookmarked clean URL",
				request: func(t *testing.T, store sessionstore.Store) *http.Request {
					return activationCleanGetRequest()
				},
				reason: "marker_missing",
			},
			{
				name: "a marker left by the reset flow",
				request: func(t *testing.T, store sessionstore.Store) *http.Request {
					return withMarker(t, store, activationCleanGetRequest(), emaillinks.LinkMarkerFlowResetPassword, 7, codeHash)
				},
				reason: "marker_wrong_flow",
			},
			{
				name: "a marker past its window",
				request: func(t *testing.T, store sessionstore.Store) *http.Request {
					return withRawMarker(t, store, activationCleanGetRequest(),
						expiredMarkerJSON(t, emaillinks.LinkMarkerFlowAccountActivate, 7, codeHash))
				},
				reason: "marker_expired",
			},
			{
				// The replay case: the activation completed, the row is gone, and a copy of
				// the cookie taken beforehand still decodes. What refuses it is the hash no
				// longer resolving, since a client-side cookie cannot be recalled.
				name: "a live marker whose code hash no longer resolves",
				request: func(t *testing.T, store sessionstore.Store) *http.Request {
					return withMarker(t, store, activationCleanGetRequest(), emaillinks.LinkMarkerFlowAccountActivate, 7, codeHash)
				},
				resolves: true,
				reason:   "code_no_longer_outstanding",
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				pageRenderer := handlersmocks.NewPageRenderer(t)
				database := datamocks.NewDatabase(t)
				auditLogger := handlersmocks.NewAuditLogger(t)
				store := newMarkerTestStore()

				if tc.resolves {
					database.On("GetPreRegistrationByVerificationCodeHash", mock.Anything, (*sql.Tx)(nil), codeHash).Return(nil, nil).Once()
				}
				expectRenderedLinkExpired(pageRenderer)
				// No preRegistrationId on any row: a rejected marker is resolved against nothing,
				// and one whose hash no longer resolves names no row.
				expectAuditFailedActivationCode(auditLogger, tc.reason, 0)

				sent := tc.request(t, store)
				logs := logtest.CaptureSlog(t)

				handler := HandleActivateGet(pageRenderer, store, database, auditLogger, testDataCipher)
				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, sent)

				assert.Equal(t, http.StatusOK, rr.Code)
				assertRefusalNotLogged(t, logs)
				database.AssertNotCalled(t, "DeletePreRegistration", mock.Anything, mock.Anything, mock.Anything)
				database.AssertExpectations(t)
				pageRenderer.AssertExpectations(t)
			})
		}
	})
}

// =============================================================================
// Self-registration switched off: both hops refuse before anything else.
// =============================================================================

// A link mailed while registration was on must not create an account after an administrator has
// turned it off. Each hop is given everything it would need to succeed, so the setting is the
// only thing that can refuse it (#425 decision 6).
func TestHandleActivateGet_SelfRegistrationDisabled(t *testing.T) {
	const code = "the-emitted-code"

	for _, tc := range []struct {
		name    string
		request func(t *testing.T, store sessionstore.Store, codeHash string) *http.Request
	}{
		{
			name: "the first hop, carrying a live code",
			request: func(t *testing.T, store sessionstore.Store, codeHash string) *http.Request {
				return activationLinkFollowedRequest(code)
			},
		},
		{
			name: "the clean hop, carrying a live marker",
			request: func(t *testing.T, store sessionstore.Store, codeHash string) *http.Request {
				return withMarker(t, store, activationCleanGetRequest(), emaillinks.LinkMarkerFlowAccountActivate, 7, codeHash)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			store := newMarkerTestStore()

			_, codeHash := preRegistrationWithCode(t, 7, activateTestEmail, code, time.Now().UTC())
			sent := withSelfRegistration(tc.request(t, store, codeHash), false)
			pageRenderer.On("NotFound", mock.Anything, mock.Anything).Once()
			logs := logtest.CaptureSlog(t)

			handler := HandleActivateGet(pageRenderer, store, database, auditLogger, testDataCipher)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, sent)

			assert.NotEqual(t, http.StatusSeeOther, rr.Code, "a refused link must not redirect")
			assertSelfRegistrationDisabledLogged(t, logs)
			database.AssertNotCalled(t, "GetPreRegistrationByVerificationCodeHash", mock.Anything, mock.Anything, mock.Anything)
			database.AssertNotCalled(t, "DeletePreRegistration", mock.Anything, mock.Anything, mock.Anything)
			pageRenderer.AssertExpectations(t)
		})
	}
}

// refuseActivationLink's audit payload, pinned directly as TestAuditFailedResetPasswordCode pins
// the reset twin's: the two entries are one shape, so a query reads both flows (#435).
func TestRefuseActivationLink_AuditPayload(t *testing.T) {
	capture := func(t *testing.T, r *http.Request, preRegistrationId int64, reason string) map[string]interface{} {
		t.Helper()
		pageRenderer := handlersmocks.NewPageRenderer(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		expectRenderedLinkExpired(pageRenderer)
		var captured map[string]interface{}
		auditLogger.On("Log", mock.Anything, audit.EventFailedAccountActivationCode, mock.Anything).
			Run(func(args mock.Arguments) {
				captured = args.Get(2).(map[string]interface{})
			}).Return().Once()

		refuseActivationLink(pageRenderer, auditLogger, httptest.NewRecorder(), r, preRegistrationId, reason, 0)
		return captured
	}

	t.Run("the client IP is always recorded and no address ever is", func(t *testing.T) {
		req := activationCleanGetRequest()
		req.RemoteAddr = "203.0.113.7:54321"

		details := capture(t, req, 0, activationReasonUnknownCode)

		assert.Equal(t, "203.0.113.7", details["ip"])
		assert.Equal(t, activationReasonUnknownCode, details["reason"])
		assert.NotContains(t, details, "email")
		assert.NotContains(t, details, "preRegistrationId",
			"an unresolved lookup must leave the key absent rather than naming row 0")
	})

	t.Run("a resolved preRegistrationId is recorded beside it", func(t *testing.T) {
		details := capture(t, activationCleanGetRequest(), 42, activationReasonCodeExpired)

		assert.Equal(t, int64(42), details["preRegistrationId"])
		assert.NotContains(t, details, "email")
	})

	// httpmw.RealIP resolves the address from a forwarded header in a proxied deployment,
	// so the entry is a sink for a value originating outside the process.
	t.Run("an oversized address is truncated", func(t *testing.T) {
		req := activationCleanGetRequest()
		req.RemoteAddr = strings.Repeat("a", 250)

		details := capture(t, req, 0, activationReasonUnknownCode)

		assert.Len(t, details["ip"], 100)
	})
}

// =============================================================================
// The POST: the choose-password form, which alone creates the account.
// =============================================================================

// activationSettings is what middleware.Settings puts on an activation request: self-registration
// on, and the policy the chosen password is held to, which the stubs pin by matching it.
var activationSettings = &record.Settings{SelfRegistrationEnabled: true, PasswordPolicy: record.PasswordPolicyMedium}

// postActivationRequest builds the form submission, to the clean URL the template's empty action
// re-submits to. continuationId is the hidden field the rendered form carries; pass "" for none.
func postActivationRequest(password, passwordConfirmation, continuationId string) *http.Request {
	form := url.Values{}
	form.Set("password", password)
	form.Set("passwordConfirmation", passwordConfirmation)
	if continuationId != "" {
		form.Set(continuationIdField, continuationId)
	}

	req := httptest.NewRequest("POST", emaillinks.AccountActivatePath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req.WithContext(reqctx.WithSettings(req.Context(), activationSettings))
}

// postActivationWithMarker is the ordinary submission: the cookies the first hop set, and the
// continuation id the form rendered from that marker carries, read back the way the clean GET
// reads it so the test cannot invent one the handler would never have rendered.
func postActivationWithMarker(t *testing.T, store sessionstore.Store, password, passwordConfirmation string,
	id int64, codeHash string) *http.Request {
	t.Helper()

	rr := httptest.NewRecorder()
	rejection, err := emaillinks.SaveLinkMarker(store, rr, activationCleanGetRequest(),
		emaillinks.LinkMarkerFlowAccountActivate, id, codeHash)
	require.NoError(t, err)
	require.Empty(t, rejection)

	carrying := activationCleanGetRequest()
	for _, c := range rr.Result().Cookies() {
		carrying.AddCookie(c)
	}
	marker, rejection, err := emaillinks.GetLinkMarker(store, carrying, emaillinks.LinkMarkerFlowAccountActivate)
	require.NoError(t, err)
	require.Empty(t, rejection)

	req := postActivationRequest(password, passwordConfirmation, marker.ContinuationId)
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}
	return req
}

// expectRenderedActivationFormError matches the choose-password form redrawn with a reason, still
// naming the address and carrying back the continuation id the submission held, so a mistyped
// confirmation does not cost the continuation.
func expectRenderedActivationFormError(pageRenderer *handlersmocks.PageRenderer, wantContinuationId string) {
	pageRenderer.On("RenderTemplate",
		mock.Anything,
		mock.Anything,
		"/layouts/auth_layout.html",
		"/account_activate_password.html",
		mock.MatchedBy(func(data map[string]interface{}) bool {
			msg, ok := data["error"].(string)
			return ok && msg != "" && data["continuationId"] == wantContinuationId &&
				data["email"] == activateTestEmail
		}),
	).Return(nil).Once()
}

func TestHandleActivatePost_HappyPath(t *testing.T) {
	const code = "the-emitted-code"
	const chosenPassword = "Str0ngP4ss!"

	pageRenderer := handlersmocks.NewPageRenderer(t)
	database := datamocks.NewDatabase(t)
	userCreator := accounthandlersmocks.NewUserCreator(t)
	passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	store := newMarkerTestStore()

	preReg, codeHash := preRegistrationWithCode(t, 7, activateTestEmail, code, time.Now().UTC())
	database.On("GetPreRegistrationByVerificationCodeHash", mock.Anything, (*sql.Tx)(nil), codeHash).Return(preReg, nil).Once()
	database.On("GetUserByEmail", mock.Anything, (*sql.Tx)(nil), activateTestEmail).Return(nil, nil).Once()
	passwordValidator.On("ValidatePassword", record.PasswordPolicyMedium, chosenPassword).Return(nil).Once()

	var created *usercreation.Input
	userCreator.On("CreateUser", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { created = args.Get(1).(*usercreation.Input) }).
		Return(&record.User{Id: 3, Email: activateTestEmail}, nil).Once()

	database.On("DeletePreRegistration", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventCreatedUser, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["email"] == activateTestEmail
	})).Return().Once()
	auditLogger.On("Log", mock.Anything, audit.EventActivatedAccount, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["email"] == activateTestEmail
	})).Return().Once()
	pageRenderer.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/auth_layout.html",
		"/account_register_activation_result.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			_, expired := data["linkHasExpired"]
			return !expired && data["adminConsoleBaseUrl"] == testAdminConsoleBaseURL
		})).Return(nil).Once()

	handler := HandleActivatePost(pageRenderer, store, database, userCreator, passwordValidator, auditLogger, testAdminConsoleBaseURL)
	rr := httptest.NewRecorder()
	sent := postActivationWithMarker(t, store, chosenPassword, chosenPassword, 7, codeHash)
	handler.ServeHTTP(rr, sent)

	assert.Equal(t, http.StatusOK, rr.Code)

	// The account gets the password typed into this form, whoever registered the address: the
	// person who proved control of the mailbox chooses it (#207 decision 1).
	require.NotNil(t, created)
	assert.Equal(t, activateTestEmail, created.Email)
	assert.True(t, created.EmailVerified, "following the emailed link proved the address")
	assert.True(t, passwordhash.Verify(created.PasswordHash, chosenPassword),
		"the account's password must be the one chosen at activation")

	_, rejection, err := emaillinks.GetLinkMarker(store, nextBrowserRequest(t, sent, rr, activationCleanGetRequest),
		emaillinks.LinkMarkerFlowAccountActivate)
	require.NoError(t, err)
	assert.Equal(t, emaillinks.LinkMarkerMissing, rejection,
		"a completed activation must clear the marker from the session")

	database.AssertExpectations(t)
	userCreator.AssertExpectations(t)
	passwordValidator.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
	pageRenderer.AssertExpectations(t)
}

// A refused password redraws the form with the reason, as the reset form does, and nothing is
// written: no account, no consumed row, no audit entry.
func TestHandleActivatePost_PasswordFieldRejections(t *testing.T) {
	const continuationId = "the-continuation-the-form-carried"
	const codeHash = "the-code-hash"

	testCases := []struct {
		name                 string
		password             string
		passwordConfirmation string
		arrange              func(passwordValidator *accounthandlersmocks.PasswordValidator)
	}{
		{
			name:     "empty password",
			password: "", passwordConfirmation: "",
			arrange: func(passwordValidator *accounthandlersmocks.PasswordValidator) {},
		},
		{
			name:     "confirmation mismatch",
			password: "Str0ngP4ss!", passwordConfirmation: "Different1!",
			arrange: func(passwordValidator *accounthandlersmocks.PasswordValidator) {},
		},
		{
			name:     "the policy refuses the password",
			password: "weak", passwordConfirmation: "weak",
			arrange: func(passwordValidator *accounthandlersmocks.PasswordValidator) {
				passwordValidator.On("ValidatePassword", record.PasswordPolicyMedium, "weak").
					Return(errs.New("too weak")).Once()
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			database := datamocks.NewDatabase(t)
			userCreator := accounthandlersmocks.NewUserCreator(t)
			passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			store := newMarkerTestStore()

			tc.arrange(passwordValidator)
			database.On("GetPreRegistrationByVerificationCodeHash", mock.Anything, (*sql.Tx)(nil), codeHash).
				Return(&record.PreRegistration{Id: 7, Email: activateTestEmail}, nil).Once()
			database.On("GetUserByEmail", mock.Anything, (*sql.Tx)(nil), activateTestEmail).Return(nil, nil).Once()
			expectRenderedActivationFormError(pageRenderer, continuationId)

			handler := HandleActivatePost(pageRenderer, store, database, userCreator, passwordValidator, auditLogger, testAdminConsoleBaseURL)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, withMarker(t, store, postActivationRequest(tc.password, tc.passwordConfirmation, continuationId),
				emaillinks.LinkMarkerFlowAccountActivate, 7, codeHash))

			assert.Equal(t, http.StatusOK, rr.Code)
			pageRenderer.AssertExpectations(t)
			database.AssertExpectations(t)
			userCreator.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
			database.AssertNotCalled(t, "DeletePreRegistration", mock.Anything, mock.Anything, mock.Anything)
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// Every refusal of the link on the POST answers the one refusal page at 400, audited with the
// reason the page withholds, and creates nothing.
func TestHandleActivatePost_RefusalsCreateNothing(t *testing.T) {
	const code = "the-emitted-code"
	const chosenPassword = "Str0ngP4ss!"
	codeHash := hashutil.HashString(code)

	for _, tc := range []struct {
		name    string
		request func(t *testing.T, store sessionstore.Store) *http.Request
		arrange func(database *datamocks.Database, passwordValidator *accounthandlersmocks.PasswordValidator)
		reason  string
		// wantPreRegistrationId is 0 where the key must be absent.
		wantPreRegistrationId int64
	}{
		{
			name: "no marker at all",
			request: func(t *testing.T, store sessionstore.Store) *http.Request {
				return postActivationRequest(chosenPassword, chosenPassword, "")
			},
			arrange: func(*datamocks.Database, *accounthandlersmocks.PasswordValidator) {},
			reason:  "marker_missing",
		},
		{
			name: "a marker left by the reset flow",
			request: func(t *testing.T, store sessionstore.Store) *http.Request {
				return withMarker(t, store, postActivationRequest(chosenPassword, chosenPassword, ""),
					emaillinks.LinkMarkerFlowResetPassword, 7, codeHash)
			},
			arrange: func(*datamocks.Database, *accounthandlersmocks.PasswordValidator) {},
			reason:  "marker_wrong_flow",
		},
		{
			name: "a marker past its window",
			request: func(t *testing.T, store sessionstore.Store) *http.Request {
				return withRawMarker(t, store, postActivationRequest(chosenPassword, chosenPassword, ""),
					expiredMarkerJSON(t, emaillinks.LinkMarkerFlowAccountActivate, 7, codeHash))
			},
			arrange: func(*datamocks.Database, *accounthandlersmocks.PasswordValidator) {},
			reason:  "marker_expired",
		},
		{
			// A replayed submission after the activation completed: the row is gone.
			name: "a live marker whose code hash no longer resolves",
			request: func(t *testing.T, store sessionstore.Store) *http.Request {
				return postActivationWithMarker(t, store, chosenPassword, chosenPassword, 7, codeHash)
			},
			arrange: func(database *datamocks.Database, _ *accounthandlersmocks.PasswordValidator) {
				database.On("GetPreRegistrationByVerificationCodeHash", mock.Anything, (*sql.Tx)(nil), codeHash).Return(nil, nil).Once()
			},
			reason: "code_no_longer_outstanding",
		},
		{
			// A page rendered for one pending registration must not activate another: the form
			// names a continuation other than the one the session holds.
			name: "a form naming another continuation",
			request: func(t *testing.T, store sessionstore.Store) *http.Request {
				return withMarker(t, store, postActivationRequest(chosenPassword, chosenPassword, "a-stale-continuation"),
					emaillinks.LinkMarkerFlowAccountActivate, 7, codeHash)
			},
			arrange: func(database *datamocks.Database, passwordValidator *accounthandlersmocks.PasswordValidator) {
				database.On("GetPreRegistrationByVerificationCodeHash", mock.Anything, (*sql.Tx)(nil), codeHash).
					Return(&record.PreRegistration{Id: 7, Email: activateTestEmail}, nil).Once()
				database.On("GetUserByEmail", mock.Anything, (*sql.Tx)(nil), activateTestEmail).Return(nil, nil).Once()
				passwordValidator.On("ValidatePassword", record.PasswordPolicyMedium, chosenPassword).Return(nil).Once()
			},
			reason:                "continuation_mismatch",
			wantPreRegistrationId: 7,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			database := datamocks.NewDatabase(t)
			userCreator := accounthandlersmocks.NewUserCreator(t)
			passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			store := newMarkerTestStore()

			tc.arrange(database, passwordValidator)
			expectRenderedLinkExpiredAt(pageRenderer, http.StatusBadRequest)
			expectAuditFailedActivationCode(auditLogger, tc.reason, tc.wantPreRegistrationId)

			sent := tc.request(t, store)
			logs := logtest.CaptureSlog(t)

			handler := HandleActivatePost(pageRenderer, store, database, userCreator, passwordValidator, auditLogger, testAdminConsoleBaseURL)
			handler.ServeHTTP(httptest.NewRecorder(), sent)

			assertRefusalNotLogged(t, logs)
			userCreator.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
			database.AssertNotCalled(t, "DeletePreRegistration", mock.Anything, mock.Anything, mock.Anything)
			database.AssertExpectations(t)
			passwordValidator.AssertExpectations(t)
			pageRenderer.AssertExpectations(t)
			auditLogger.AssertExpectations(t)
		})
	}
}

// An address that gained an account is refused at the POST too, both when the lookup sees it and
// when the insert loses the race on the unique email index, which the data layer reports as
// data.ErrUniqueViolation. Each deletes the pending registration, which can never complete, and
// answers the refusal page at 400 audited as address_taken (#207 decision 10). The lost race used
// to answer the 500 page with an error-level stack.
func TestHandleActivatePost_AddressTaken(t *testing.T) {
	const code = "the-emitted-code"
	const chosenPassword = "Str0ngP4ss!"

	t.Run("the lookup finds an account, before the password is looked at", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		userCreator := accounthandlersmocks.NewUserCreator(t)
		passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		store := newMarkerTestStore()

		preReg, codeHash := preRegistrationWithCode(t, 7, activateTestEmail, code, time.Now().UTC())
		database.On("GetPreRegistrationByVerificationCodeHash", mock.Anything, (*sql.Tx)(nil), codeHash).Return(preReg, nil).Once()
		database.On("GetUserByEmail", mock.Anything, (*sql.Tx)(nil), activateTestEmail).
			Return(&record.User{Id: 3, Email: activateTestEmail}, nil).Once()
		database.On("DeletePreRegistration", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(nil).Once()
		expectRenderedLinkExpiredAt(pageRenderer, http.StatusBadRequest)
		expectAuditFailedActivationCode(auditLogger, "address_taken", 7)

		handler := HandleActivatePost(pageRenderer, store, database, userCreator, passwordValidator, auditLogger, testAdminConsoleBaseURL)
		handler.ServeHTTP(httptest.NewRecorder(), postActivationWithMarker(t, store, chosenPassword, chosenPassword, 7, codeHash))

		userCreator.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
		passwordValidator.AssertNotCalled(t, "ValidatePassword", mock.Anything, mock.Anything)
		database.AssertExpectations(t)
		pageRenderer.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("the insert loses the race on the unique email index", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		userCreator := accounthandlersmocks.NewUserCreator(t)
		passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		store := newMarkerTestStore()
		logs := logtest.CaptureSlog(t)

		preReg, codeHash := preRegistrationWithCode(t, 7, activateTestEmail, code, time.Now().UTC())
		database.On("GetPreRegistrationByVerificationCodeHash", mock.Anything, (*sql.Tx)(nil), codeHash).Return(preReg, nil).Once()
		database.On("GetUserByEmail", mock.Anything, (*sql.Tx)(nil), activateTestEmail).Return(nil, nil).Once()
		passwordValidator.On("ValidatePassword", record.PasswordPolicyMedium, chosenPassword).Return(nil).Once()
		userCreator.On("CreateUser", mock.Anything, mock.Anything).
			Return(nil, errs.Wrap(data.ErrUniqueViolation, "unable to insert user")).Once()
		database.On("DeletePreRegistration", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(nil).Once()
		expectRenderedLinkExpiredAt(pageRenderer, http.StatusBadRequest)
		expectAuditFailedActivationCode(auditLogger, "address_taken", 7)

		handler := HandleActivatePost(pageRenderer, store, database, userCreator, passwordValidator, auditLogger, testAdminConsoleBaseURL)
		handler.ServeHTTP(httptest.NewRecorder(), postActivationWithMarker(t, store, chosenPassword, chosenPassword, 7, codeHash))

		assertRefusalNotLogged(t, logs)
		database.AssertExpectations(t)
		userCreator.AssertExpectations(t)
		pageRenderer.AssertExpectations(t)
		// The strict mock holds the entries to the one refusal: no created_user, no activated_account.
		auditLogger.AssertExpectations(t)
	})

	// Any other insert failure is a server fault, not a refusal: the 500 page, the pending
	// registration left alone, and no entry filing it under the link.
	t.Run("another insert failure stays a server error", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		userCreator := accounthandlersmocks.NewUserCreator(t)
		passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		store := newMarkerTestStore()

		preReg, codeHash := preRegistrationWithCode(t, 7, activateTestEmail, code, time.Now().UTC())
		database.On("GetPreRegistrationByVerificationCodeHash", mock.Anything, (*sql.Tx)(nil), codeHash).Return(preReg, nil).Once()
		database.On("GetUserByEmail", mock.Anything, (*sql.Tx)(nil), activateTestEmail).Return(nil, nil).Once()
		passwordValidator.On("ValidatePassword", record.PasswordPolicyMedium, chosenPassword).Return(nil).Once()
		userCreator.On("CreateUser", mock.Anything, mock.Anything).Return(nil, errs.New("connection reset")).Once()
		pageRenderer.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Once()

		handler := HandleActivatePost(pageRenderer, store, database, userCreator, passwordValidator, auditLogger, testAdminConsoleBaseURL)
		handler.ServeHTTP(httptest.NewRecorder(), postActivationWithMarker(t, store, chosenPassword, chosenPassword, 7, codeHash))

		database.AssertNotCalled(t, "DeletePreRegistration", mock.Anything, mock.Anything, mock.Anything)
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		pageRenderer.AssertExpectations(t)
	})
}

// The POST refuses while self-registration is off, like both GET hops, given everything it would
// need to succeed (#425 decision 6).
func TestHandleActivatePost_SelfRegistrationDisabled(t *testing.T) {
	pageRenderer := handlersmocks.NewPageRenderer(t)
	database := datamocks.NewDatabase(t)
	userCreator := accounthandlersmocks.NewUserCreator(t)
	passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	store := newMarkerTestStore()

	sent := withSelfRegistration(postActivationWithMarker(t, store, "Str0ngP4ss!", "Str0ngP4ss!", 7, "the-code-hash"), false)
	pageRenderer.On("NotFound", mock.Anything, mock.Anything).Once()
	logs := logtest.CaptureSlog(t)

	handler := HandleActivatePost(pageRenderer, store, database, userCreator, passwordValidator, auditLogger, testAdminConsoleBaseURL)
	handler.ServeHTTP(httptest.NewRecorder(), sent)

	assertSelfRegistrationDisabledLogged(t, logs)
	database.AssertNotCalled(t, "GetPreRegistrationByVerificationCodeHash", mock.Anything, mock.Anything, mock.Anything)
	userCreator.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
	pageRenderer.AssertExpectations(t)
}
