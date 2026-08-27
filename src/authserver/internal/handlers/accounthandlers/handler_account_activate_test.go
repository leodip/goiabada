package accounthandlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/core/constants"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/encryption"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/user"
	mocks_users "github.com/leodip/goiabada/core/user/mocks"
)

// The activation flow's state machine, at seam 3.
//
// Every case here drives a URL the handler itself would produce: a first hop carrying only
// ?code=, or a clean hop carrying no query at all. That is the whole change (#112): the link
// used to carry ?email= too, and form-urlencoded query parsing turned a '+' in the address
// into a space, so the pre-registration was never found.

// A real store rather than the mock, because these cases turn on the marker surviving a
// round trip between the two hops and a mock cannot show one. A ServerSideStore over an
// in-memory backend since #266 moved the session out of the browser; what these cases
// assert is unchanged by that, since the marker round-trips either way.
func newMarkerTestStore() *sessionstore.ServerSideStore {
	return sessionstore.NewServerSideStore(
		sessionstore.NewMemoryBackend(),
		constants.SessionKeySessionIdentifier,
		false,
		[]byte("12345678901234567890123456789012"),
		[]byte("abcdefghijklmnopqrstuvwxyz123456"),
	)
}

// linkFollowedRequest is the emailed link being followed: the code, and nothing else.
func linkFollowedRequest(code string) *http.Request {
	target := handlers.AccountActivatePath
	if code != "" {
		target += "?" + url.Values{"code": {code}}.Encode()
	}
	return httptest.NewRequest("GET", target, nil)
}

// cleanGetRequest is where the first hop's 303 lands: the same path, no query at all.
func cleanGetRequest() *http.Request {
	return httptest.NewRequest("GET", handlers.AccountActivatePath, nil)
}

// withMarker attaches the session cookies a first hop would have set, which is what makes a
// request a clean-hop request rather than a bare one.
func withMarker(t *testing.T, store sessions.Store, req *http.Request, flow handlers.LinkMarkerFlow,
	id int64, codeHash string) *http.Request {
	t.Helper()

	rr := httptest.NewRecorder()
	rejection, err := handlers.SaveLinkMarker(store, rr, cleanGetRequest(), flow, id, codeHash)
	require.NoError(t, err)
	require.Empty(t, rejection)
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}
	return req
}

// withRawMarker attaches cookies holding an arbitrary marker value, for the one state
// SaveLinkMarker cannot produce: a marker already past its window.
func withRawMarker(t *testing.T, store sessions.Store, req *http.Request, value interface{}) *http.Request {
	t.Helper()

	seed := cleanGetRequest()
	rr := httptest.NewRecorder()
	sess, err := store.Get(seed, constants.AuthServerSessionName)
	require.NoError(t, err)
	sess.Values[constants.SessionKeyLinkMarker] = value
	require.NoError(t, store.Save(seed, rr, sess))

	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}
	return req
}

// expiredMarkerJSON is a marker already past its window.
func expiredMarkerJSON(t *testing.T, flow handlers.LinkMarkerFlow, id int64, codeHash string) string {
	t.Helper()

	data, err := json.Marshal(&handlers.LinkMarker{
		Flow:      flow,
		Id:        id,
		CodeHash:  codeHash,
		ExpiresAt: time.Now().UTC().Add(-time.Second),
	})
	require.NoError(t, err)
	return string(data)
}

// nextBrowserRequest models what the browser sends after this exchange: the cookies it already
// held, with the response's Set-Cookie applied on top.
//
// Building it from the response alone would be vacuous for anything that asserts a cookie is
// GONE, since a handler that set no cookie at all produces the same empty request as one that
// cleared it. That defect was real in the reset flow's tests and is not repeated here.
func nextBrowserRequest(t *testing.T, sent *http.Request, rr *httptest.ResponseRecorder) *http.Request {
	t.Helper()

	byName := map[string]*http.Cookie{}
	for _, c := range sent.Cookies() {
		byName[c.Name] = c
	}
	for _, c := range rr.Result().Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(byName, c.Name)
			continue
		}
		byName[c.Name] = c
	}

	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)

	next := cleanGetRequest()
	for _, name := range names {
		next.AddCookie(byName[name])
	}
	return next
}

// preRegistrationWithCode builds a pending registration holding an outstanding activation
// code, along with the hash the link's code resolves to.
func preRegistrationWithCode(t *testing.T, id int64, email, code string, issuedAt time.Time) (*models.PreRegistration, string) {
	t.Helper()

	encrypted, err := encryption.EncryptData(code)
	require.NoError(t, err)
	codeHash, err := hashutil.HashString(code)
	require.NoError(t, err)

	return &models.PreRegistration{
		Id:                        id,
		Email:                     email,
		PasswordHash:              "password_hash",
		VerificationCodeEncrypted: encrypted,
		VerificationCodeHash:      codeHash,
		VerificationCodeIssuedAt:  sql.NullTime{Time: issuedAt, Valid: true},
	}, codeHash
}

// expectRenderedLinkExpired matches the one response every marker-attributable failure must
// produce: the activation result page in its "register again" state. A single matcher
// everywhere is deliberate, since these paths differing would tell a caller which of them
// happened.
func expectRenderedLinkExpired(httpHelper *mocks_handlerhelpers.HttpHelper) {
	httpHelper.On("RenderTemplate",
		mock.Anything,
		mock.Anything,
		"/layouts/auth_layout.html",
		"/account_register_activation_result.html",
		mock.MatchedBy(func(data map[string]interface{}) bool {
			flag, ok := data["linkHasExpired"].(bool)
			return ok && flag
		}),
	).Return(nil).Once()
}

// The '+' address is the class #112 reports as broken, and it is used throughout so that a
// regression putting the address back into the link cannot pass these tests.
const activateTestEmail = "user+tag@example.com"

// =============================================================================
// The first hop: the emailed link, carrying the code and nothing else.
// =============================================================================

func TestHandleAccountActivateGet_LinkFollowed(t *testing.T) {
	const code = "the-emitted-code"

	t.Run("a valid code marks the session and redirects to a clean URL", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_users.NewUserCreator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		store := newMarkerTestStore()

		preReg, codeHash := preRegistrationWithCode(t, 7, activateTestEmail, code, time.Now().UTC().Add(-time.Minute))
		database.On("GetPreRegistrationByVerificationCodeHash", (*sql.Tx)(nil), codeHash).Return(preReg, nil).Once()

		handler := HandleAccountActivateGet(httpHelper, store, database, userCreator, auditLogger)
		rr := httptest.NewRecorder()
		sent := linkFollowedRequest(code)
		handler.ServeHTTP(rr, sent)

		require.Equal(t, http.StatusSeeOther, rr.Code)

		location, err := url.Parse(rr.Header().Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, handlers.AccountActivatePath, location.Path)
		assert.Empty(t, location.RawQuery,
			"the redirect target must carry no query, so the code cannot persist in history or a Referer")

		// The account is NOT created on this hop, and the row is NOT consumed: a link
		// previewer prefetching the URL must leave the code usable (#112 decision 7).
		userCreator.AssertNotCalled(t, "CreateUser", mock.Anything)
		database.AssertNotCalled(t, "DeletePreRegistration", mock.Anything, mock.Anything)

		marker, rejection, err := handlers.GetLinkMarker(store, nextBrowserRequest(t, sent, rr),
			handlers.LinkMarkerFlowAccountActivate)
		require.NoError(t, err)
		require.Empty(t, rejection)
		require.NotNil(t, marker)
		assert.Equal(t, codeHash, marker.CodeHash,
			"the marker must name the code hash, which is what stops it outliving the activation")
		assert.Equal(t, int64(7), marker.Id)

		database.AssertExpectations(t)
	})

	t.Run("a code matching no row is refused", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_users.NewUserCreator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		store := newMarkerTestStore()

		codeHash, err := hashutil.HashString(code)
		require.NoError(t, err)
		database.On("GetPreRegistrationByVerificationCodeHash", (*sql.Tx)(nil), codeHash).Return(nil, nil).Once()
		httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Once()

		handler := HandleAccountActivateGet(httpHelper, store, database, userCreator, auditLogger)
		handler.ServeHTTP(httptest.NewRecorder(), linkFollowedRequest(code))

		userCreator.AssertNotCalled(t, "CreateUser", mock.Anything)
		database.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})

	t.Run("a hash hit whose stored code does not match is refused", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_users.NewUserCreator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		store := newMarkerTestStore()

		// Reachable only through a SHA-256 collision, and asserted so the comparison behind
		// the index stays load-bearing rather than decorative.
		preReg, _ := preRegistrationWithCode(t, 7, activateTestEmail, "a-different-code", time.Now().UTC())
		codeHash, err := hashutil.HashString(code)
		require.NoError(t, err)
		database.On("GetPreRegistrationByVerificationCodeHash", (*sql.Tx)(nil), codeHash).Return(preReg, nil).Once()
		httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Once()

		handler := HandleAccountActivateGet(httpHelper, store, database, userCreator, auditLogger)
		rr := httptest.NewRecorder()
		sent := linkFollowedRequest(code)
		handler.ServeHTTP(rr, sent)

		userCreator.AssertNotCalled(t, "CreateUser", mock.Anything)

		_, rejection, err := handlers.GetLinkMarker(store, nextBrowserRequest(t, sent, rr),
			handlers.LinkMarkerFlowAccountActivate)
		require.NoError(t, err)
		assert.Equal(t, handlers.LinkMarkerMissing, rejection,
			"a refused code must not leave a usable marker behind")

		database.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})

	// The activation half of the same defect: the clean hop reads the marker alone, so two
	// interleaved first hops used to make the redirect already in flight activate the other
	// registration. First writer wins instead (#112 decision 13).
	t.Run("a second link followed while one is in flight is refused", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_users.NewUserCreator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		store := newMarkerTestStore()

		// The second link is valid on its own: it is refused for the marker it would have
		// replaced, not for anything wrong with it.
		preReg, codeHash := preRegistrationWithCode(t, 99, "second@example.com", code, time.Now().UTC().Add(-time.Minute))
		database.On("GetPreRegistrationByVerificationCodeHash", (*sql.Tx)(nil), codeHash).Return(preReg, nil).Once()
		expectRenderedLinkExpired(httpHelper)

		sent := withMarker(t, store, linkFollowedRequest(code),
			handlers.LinkMarkerFlowAccountActivate, 7, "the-first-hash")

		handler := HandleAccountActivateGet(httpHelper, store, database, userCreator, auditLogger)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, sent)

		assert.NotEqual(t, http.StatusSeeOther, rr.Code, "a refused second link must not redirect")
		userCreator.AssertNotCalled(t, "CreateUser", mock.Anything)
		database.AssertNotCalled(t, "DeletePreRegistration", mock.Anything, mock.Anything)

		// The first continuation survives, so the redirect already in flight still activates
		// the registration whose link produced it.
		marker, rejection, err := handlers.GetLinkMarker(store, nextBrowserRequest(t, sent, rr),
			handlers.LinkMarkerFlowAccountActivate)
		require.NoError(t, err)
		require.Empty(t, rejection)
		require.NotNil(t, marker)
		assert.Equal(t, "the-first-hash", marker.CodeHash)
		assert.Equal(t, int64(7), marker.Id)

		database.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})

	// The same refusal against a live marker of the OTHER flow. Scoping the rule to one flow
	// left a bridge: one cross-flow replacement is harmless because every consuming step
	// refuses a wrong-flow marker, but a second replacement puts the slot back into the flow
	// it started in, which is the retarget in three navigations rather than one
	// (#112 decision 14).
	t.Run("a link followed while a reset continuation is in flight is refused", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_users.NewUserCreator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		store := newMarkerTestStore()

		preReg, codeHash := preRegistrationWithCode(t, 99, "second@example.com", code, time.Now().UTC().Add(-time.Minute))
		database.On("GetPreRegistrationByVerificationCodeHash", (*sql.Tx)(nil), codeHash).Return(preReg, nil).Once()
		expectRenderedLinkExpired(httpHelper)

		sent := withMarker(t, store, linkFollowedRequest(code),
			handlers.LinkMarkerFlowResetPassword, 42, "the-reset-hash")

		handler := HandleAccountActivateGet(httpHelper, store, database, userCreator, auditLogger)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, sent)

		assert.NotEqual(t, http.StatusSeeOther, rr.Code, "a refused link must not redirect")
		userCreator.AssertNotCalled(t, "CreateUser", mock.Anything)
		database.AssertNotCalled(t, "DeletePreRegistration", mock.Anything, mock.Anything)

		marker, rejection, err := handlers.GetLinkMarker(store, nextBrowserRequest(t, sent, rr),
			handlers.LinkMarkerFlowResetPassword)
		require.NoError(t, err)
		require.Empty(t, rejection)
		require.NotNil(t, marker)
		assert.Equal(t, "the-reset-hash", marker.CodeHash,
			"the reset continuation must still own the session")

		database.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})

	t.Run("an expired code deletes the pending registration and asks for another", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_users.NewUserCreator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		store := newMarkerTestStore()

		preReg, codeHash := preRegistrationWithCode(t, 7, activateTestEmail, code, time.Now().UTC().Add(-6*time.Minute))
		database.On("GetPreRegistrationByVerificationCodeHash", (*sql.Tx)(nil), codeHash).Return(preReg, nil).Once()
		database.On("DeletePreRegistration", (*sql.Tx)(nil), int64(7)).Return(nil).Once()
		expectRenderedLinkExpired(httpHelper)

		handler := HandleAccountActivateGet(httpHelper, store, database, userCreator, auditLogger)
		handler.ServeHTTP(httptest.NewRecorder(), linkFollowedRequest(code))

		userCreator.AssertNotCalled(t, "CreateUser", mock.Anything)
		database.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})

	t.Run("the code's lifetime boundary", func(t *testing.T) {
		// Both sides of the 5-minute window, so the constant cannot be widened or narrowed
		// without a test noticing.
		for _, tc := range []struct {
			name     string
			issuedAt time.Time
			expired  bool
		}{
			{"just inside the window", time.Now().UTC().Add(-verificationCodeLifetime + 2*time.Second), false},
			{"just outside the window", time.Now().UTC().Add(-verificationCodeLifetime - 2*time.Second), true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
				database := mocks_data.NewDatabase(t)
				userCreator := mocks_users.NewUserCreator(t)
				auditLogger := mocks_audit.NewAuditLogger(t)
				store := newMarkerTestStore()

				preReg, codeHash := preRegistrationWithCode(t, 7, activateTestEmail, code, tc.issuedAt)
				database.On("GetPreRegistrationByVerificationCodeHash", (*sql.Tx)(nil), codeHash).Return(preReg, nil).Once()
				if tc.expired {
					database.On("DeletePreRegistration", (*sql.Tx)(nil), int64(7)).Return(nil).Once()
					expectRenderedLinkExpired(httpHelper)
				}

				handler := HandleAccountActivateGet(httpHelper, store, database, userCreator, auditLogger)
				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, linkFollowedRequest(code))

				if tc.expired {
					assert.NotEqual(t, http.StatusSeeOther, rr.Code)
				} else {
					assert.Equal(t, http.StatusSeeOther, rr.Code)
				}

				database.AssertExpectations(t)
				httpHelper.AssertExpectations(t)
			})
		}
	})
}

// =============================================================================
// The clean hop: no query at all, the marker alone.
// =============================================================================

func TestHandleAccountActivateGet_Clean(t *testing.T) {
	const code = "the-emitted-code"

	t.Run("the marker completes the activation", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_users.NewUserCreator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		store := newMarkerTestStore()

		preReg, codeHash := preRegistrationWithCode(t, 7, activateTestEmail, code, time.Now().UTC())
		database.On("GetPreRegistrationByVerificationCodeHash", (*sql.Tx)(nil), codeHash).Return(preReg, nil).Once()

		createdUser := &models.User{Id: 3, Email: activateTestEmail}
		userCreator.On("CreateUser", &user.CreateUserInput{
			Email:         activateTestEmail,
			EmailVerified: true,
			PasswordHash:  "password_hash",
		}).Return(createdUser, nil).Once()

		database.On("DeletePreRegistration", (*sql.Tx)(nil), int64(7)).Return(nil).Once()
		auditLogger.On("Log", constants.AuditCreatedUser, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["email"] == activateTestEmail
		})).Return().Once()
		auditLogger.On("Log", constants.AuditActivatedAccount, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["email"] == activateTestEmail
		})).Return().Once()
		httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/auth_layout.html",
			"/account_register_activation_result.html", mock.MatchedBy(func(data map[string]interface{}) bool {
				_, expired := data["linkHasExpired"]
				return !expired
			})).Return(nil).Once()

		handler := HandleAccountActivateGet(httpHelper, store, database, userCreator, auditLogger)
		rr := httptest.NewRecorder()
		sent := withMarker(t, store, cleanGetRequest(), handlers.LinkMarkerFlowAccountActivate, 7, codeHash)
		handler.ServeHTTP(rr, sent)

		_, rejection, err := handlers.GetLinkMarker(store, nextBrowserRequest(t, sent, rr),
			handlers.LinkMarkerFlowAccountActivate)
		require.NoError(t, err)
		assert.Equal(t, handlers.LinkMarkerMissing, rejection,
			"a completed activation must clear the marker from the session")

		database.AssertExpectations(t)
		userCreator.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})

	t.Run("every marker-attributable refusal renders the same page and creates nothing", func(t *testing.T) {
		codeHash, err := hashutil.HashString(code)
		require.NoError(t, err)

		for _, tc := range []struct {
			name    string
			request func(t *testing.T, store sessions.Store) *http.Request
			// resolves is true when the handler gets far enough to look the hash up.
			resolves bool
		}{
			{
				name: "no marker at all, a bookmarked clean URL",
				request: func(t *testing.T, store sessions.Store) *http.Request {
					return cleanGetRequest()
				},
			},
			{
				name: "a marker left by the reset flow",
				request: func(t *testing.T, store sessions.Store) *http.Request {
					return withMarker(t, store, cleanGetRequest(), handlers.LinkMarkerFlowResetPassword, 7, codeHash)
				},
			},
			{
				name: "a marker past its window",
				request: func(t *testing.T, store sessions.Store) *http.Request {
					return withRawMarker(t, store, cleanGetRequest(),
						expiredMarkerJSON(t, handlers.LinkMarkerFlowAccountActivate, 7, codeHash))
				},
			},
			{
				// The replay case: the activation completed, the row is gone, and a copy of
				// the cookie taken beforehand still decodes. What refuses it is the hash no
				// longer resolving, since a client-side cookie cannot be recalled.
				name: "a live marker whose code hash no longer resolves",
				request: func(t *testing.T, store sessions.Store) *http.Request {
					return withMarker(t, store, cleanGetRequest(), handlers.LinkMarkerFlowAccountActivate, 7, codeHash)
				},
				resolves: true,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
				database := mocks_data.NewDatabase(t)
				userCreator := mocks_users.NewUserCreator(t)
				auditLogger := mocks_audit.NewAuditLogger(t)
				store := newMarkerTestStore()

				if tc.resolves {
					database.On("GetPreRegistrationByVerificationCodeHash", (*sql.Tx)(nil), codeHash).Return(nil, nil).Once()
				}
				expectRenderedLinkExpired(httpHelper)

				handler := HandleAccountActivateGet(httpHelper, store, database, userCreator, auditLogger)
				handler.ServeHTTP(httptest.NewRecorder(), tc.request(t, store))

				userCreator.AssertNotCalled(t, "CreateUser", mock.Anything)
				database.AssertNotCalled(t, "DeletePreRegistration", mock.Anything, mock.Anything)
				database.AssertExpectations(t)
				httpHelper.AssertExpectations(t)
			})
		}
	})
}
