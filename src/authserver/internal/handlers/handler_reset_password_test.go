package handlers

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	"github.com/leodip/goiabada/core/constants"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/encryption"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
	mocks_validators "github.com/leodip/goiabada/core/validators/mocks"
)

// The address httptest.NewRequest gives every request, which is what the audit entry now
// records in place of the email address.
const testClientIP = "192.0.2.1"

// expectRenderedCodeInvalid matches the one response that every link-attributable
// failure must produce: the reset form in its invalid-or-expired state, with a
// 400. Using a single matcher everywhere is deliberate — if any of these paths
// starts answering differently, it becomes an oracle for whether an email address
// has an account, and these tests fail.
// wantStatus is the expected _httpStatus; pass 0 to require that no status is set,
// which is how the GET keeps its long-standing implicit 200.
func expectRenderedCodeInvalid(httpHelper *mocks_handlerhelpers.HttpHelper, wantStatus int) {
	httpHelper.On("RenderTemplate",
		mock.Anything,
		mock.Anything,
		"/layouts/auth_layout.html",
		"/reset_password.html",
		mock.MatchedBy(func(data map[string]interface{}) bool {
			flag, ok := data["codeInvalidOrExpired"].(bool)
			if !ok || !flag {
				return false
			}
			status, present := data["_httpStatus"]
			if wantStatus == 0 {
				return !present
			}
			return present && status == wantStatus
		}),
	).Return(nil).Once()
}

// expectAuditFailedCode requires exactly one audit entry for a refused request,
// carrying the given reason. The reason is the only place the cause is recorded,
// since every refusal returns the same response.
//
// It also pins the payload's shape, which changed with #112: the client IP is always
// present, no address appears anywhere, and userId appears only on the branches where the
// lookup actually resolved a user. Pass wantUserId 0 to require the key is ABSENT rather
// than zero, since a payload naming user 0 asserts a row that does not exist.
func expectAuditFailedCode(auditLogger *mocks_audit.AuditLogger, wantReason string, wantUserId int64) {
	auditLogger.On("Log", constants.AuditFailedResetPasswordCode,
		mock.MatchedBy(func(details map[string]interface{}) bool {
			if details["reason"] != wantReason || details["ip"] != testClientIP {
				return false
			}
			// The address left the request entirely; putting one back would undo half of
			// what this change removed.
			if _, present := details["email"]; present {
				return false
			}
			userId, present := details["userId"]
			if wantUserId == 0 {
				return !present
			}
			return present && userId == wantUserId
		}),
	).Return().Once()
}

// linkFollowedRequest is the emailed link being followed: the code, and nothing else.
func linkFollowedRequest(code string) *http.Request {
	target := ResetPasswordPath
	if code != "" {
		target += "?" + url.Values{"code": {code}}.Encode()
	}
	return httptest.NewRequest("GET", target, nil)
}

// cleanGetRequest is where the first hop's 303 lands: the same path, no query at all.
func cleanGetRequest() *http.Request {
	return httptest.NewRequest("GET", ResetPasswordPath, nil)
}

// postResetRequest builds the form submission. It carries no query either: the template's
// empty action re-submits to whatever URL the GET was served from, which after the redirect
// is the clean one.
// continuationId is the hidden field the rendered form carries; pass "" for the states
// that never reach the check, and a wrong value for the retarget cases.
func postResetRequest(password, passwordConfirmation, continuationId string) *http.Request {
	form := url.Values{}
	form.Set("password", password)
	form.Set("passwordConfirmation", passwordConfirmation)
	if continuationId != "" {
		form.Set(continuationIdField, continuationId)
	}

	req := httptest.NewRequest("POST", ResetPasswordPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// postWithMarker is the ordinary submission: the cookies a first hop of flow set, and the
// continuation id the form rendered from that marker would have carried. Built together
// because the id only exists once the marker does, which is exactly the coupling the check
// enforces at runtime.
func postWithMarker(t *testing.T, store sessions.Store, password, passwordConfirmation string,
	flow LinkMarkerFlow, id int64, codeHash string) *http.Request {
	t.Helper()

	rr := httptest.NewRecorder()
	rejection, err := SaveLinkMarker(store, rr, cleanGetRequest(), flow, id, codeHash)
	require.NoError(t, err)
	require.Empty(t, rejection)

	// Read the id back the way the clean GET does, so the test cannot invent one the
	// handler would never have rendered.
	carrying := cleanGetRequest()
	for _, c := range rr.Result().Cookies() {
		carrying.AddCookie(c)
	}
	marker, rejection, err := GetLinkMarker(store, carrying, flow)
	require.NoError(t, err)
	require.Empty(t, rejection)
	require.NotNil(t, marker)

	req := postResetRequest(password, passwordConfirmation, marker.ContinuationId)
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}
	return req
}

// withMarker attaches the session cookies a first hop would have set, which is what makes a
// request a clean-hop request rather than a bare one.
func withMarker(t *testing.T, store sessions.Store, req *http.Request, flow LinkMarkerFlow,
	id int64, codeHash string) *http.Request {
	t.Helper()

	rr := httptest.NewRecorder()
	rejection, err := SaveLinkMarker(store, rr, cleanGetRequest(), flow, id, codeHash)
	require.NoError(t, err)
	require.Empty(t, rejection)
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}
	return req
}

// postResetWithCredentialsInQuery is postResetRequest with the two credential fields moved
// into the request target. The continuation id stays in the body, so the submission is a
// legitimate one in every respect but where the password came from, and the handler's answer
// is the whole assertion: r.FormValue merges the query behind the body, so it would set a
// password taken from a URL, where it reaches history, Referer and every proxy log in front
// of the deployment (#202).
func postResetWithCredentialsInQuery(password, passwordConfirmation, continuationId string) *http.Request {
	form := url.Values{}
	if continuationId != "" {
		form.Set(continuationIdField, continuationId)
	}

	query := url.Values{}
	query.Set("password", password)
	query.Set("passwordConfirmation", passwordConfirmation)

	req := httptest.NewRequest("POST", ResetPasswordPath+"?"+query.Encode(),
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// postWithMarkerContinuationInQuery is postWithMarker with the continuation id moved into the
// request target and left out of the body. The id is the marker's own live one, read back
// through GetLinkMarker exactly as postWithMarker does so the test cannot invent one the
// handler would never have rendered: the gate must still refuse it, because a marker supplied
// by a URL is not a submission and reading one from a URL reintroduces the shape #201 removed
// from the reset link, one indirection later (#202, decision 3).
func postWithMarkerContinuationInQuery(t *testing.T, store sessions.Store,
	password, passwordConfirmation string, flow LinkMarkerFlow, id int64, codeHash string) *http.Request {
	t.Helper()

	rr := httptest.NewRecorder()
	rejection, err := SaveLinkMarker(store, rr, cleanGetRequest(), flow, id, codeHash)
	require.NoError(t, err)
	require.Empty(t, rejection)

	carrying := cleanGetRequest()
	for _, c := range rr.Result().Cookies() {
		carrying.AddCookie(c)
	}
	marker, rejection, err := GetLinkMarker(store, carrying, flow)
	require.NoError(t, err)
	require.Empty(t, rejection)
	require.NotNil(t, marker)
	require.NotEmpty(t, marker.ContinuationId)

	form := url.Values{}
	form.Set("password", password)
	form.Set("passwordConfirmation", passwordConfirmation)

	query := url.Values{continuationIdField: {marker.ContinuationId}}
	req := httptest.NewRequest("POST", ResetPasswordPath+"?"+query.Encode(),
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}
	return req
}

// withRawMarker attaches cookies holding an arbitrary marker value, for the states
// SaveLinkMarker cannot produce: an already-expired marker, and a corrupt one.
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

// nextBrowserRequest models what the browser sends after this exchange: the cookies it
// already held, with the response's Set-Cookie applied on top.
//
// Building it from the response alone would be vacuous for anything that asserts a cookie is
// GONE: a handler that set no cookie at all produces the same empty request as one that
// cleared it, so such an assertion passes against code that never clears anything.
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

// expiredMarkerJSON is a marker already past its window, which SaveLinkMarker cannot write.
func expiredMarkerJSON(t *testing.T, flow LinkMarkerFlow, id int64, codeHash string) string {
	t.Helper()
	return marshalMarker(t, &LinkMarker{
		Flow:      flow,
		Id:        id,
		CodeHash:  codeHash,
		ExpiresAt: time.Now().UTC().Add(-time.Second),
	})
}

// userWithCode builds a user holding an outstanding reset code, along with the code and the
// hash the link would carry.
func userWithCode(t *testing.T, id int64, code string, issuedAt time.Time) (*models.User, string) {
	t.Helper()

	encrypted, err := encryption.EncryptData(code)
	require.NoError(t, err)
	codeHash, err := hashutil.HashString(code)
	require.NoError(t, err)

	return &models.User{
		Id:                          id,
		Email:                       "test@example.com",
		ForgotPasswordCodeEncrypted: encrypted,
		ForgotPasswordCodeHash:      codeHash,
		ForgotPasswordCodeIssuedAt:  sql.NullTime{Time: issuedAt, Valid: true},
	}, codeHash
}

// =============================================================================
// The first hop: the emailed link, carrying the code and nothing else.
// =============================================================================

func TestHandleResetPasswordGet_LinkFollowed(t *testing.T) {
	const code = "the-emitted-code"

	t.Run("a valid code marks the session and redirects to a clean URL", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		store := newMarkerTestStore()

		user, codeHash := userWithCode(t, 1, code, time.Now().UTC().Add(-time.Minute))
		database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), codeHash).Return(user, nil).Once()

		handler := HandleResetPasswordGet(httpHelper, store, database, auditLogger)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, linkFollowedRequest(code))

		// 303 rather than 302: the browser must follow with a GET, and the code is gone
		// from the request target from here on.
		require.Equal(t, http.StatusSeeOther, rr.Code)
		location, err := url.Parse(rr.Header().Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, ResetPasswordPath, location.Path)
		assert.Empty(t, location.RawQuery, "the redirect target must carry no query at all")

		// The marker names the code hash, which is what the clean steps re-resolve.
		marker, rejection, err := GetLinkMarker(store, requestCarrying(t, rr), LinkMarkerFlowResetPassword)
		require.NoError(t, err)
		require.Empty(t, rejection)
		require.NotNil(t, marker)
		assert.Equal(t, codeHash, marker.CodeHash)
		assert.Equal(t, int64(1), marker.Id)

		database.AssertExpectations(t)
	})

	// Every rejection below leaves no marker behind and does not redirect, so nothing
	// downstream can be reached with a code that did not validate.
	rejections := []struct {
		name       string
		arrange    func(t *testing.T, database *mocks_data.Database)
		wantReason string
		wantUserId int64
	}{
		{
			name: "a code matching no outstanding reset",
			arrange: func(t *testing.T, database *mocks_data.Database) {
				codeHash, err := hashutil.HashString(code)
				require.NoError(t, err)
				database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), codeHash).
					Return(nil, nil).Once()
			},
			wantReason: auditReasonUnknownCode,
		},
		{
			// A SHA-256 collision is not reachable in practice; what this pins is that the
			// index only nominates a candidate and the constant-time compare decides. Without
			// it the lookup alone would be the authority.
			name: "a row found by hash whose stored code does not match",
			arrange: func(t *testing.T, database *mocks_data.Database) {
				other, _ := userWithCode(t, 1, "a-completely-different-code", time.Now().UTC())
				codeHash, err := hashutil.HashString(code)
				require.NoError(t, err)
				database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), codeHash).
					Return(other, nil).Once()
			},
			wantReason: auditReasonUnknownCode,
		},
		{
			name: "a row carrying a hash but no encrypted code",
			arrange: func(t *testing.T, database *mocks_data.Database) {
				codeHash, err := hashutil.HashString(code)
				require.NoError(t, err)
				database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), codeHash).
					Return(&models.User{Id: 1, ForgotPasswordCodeHash: codeHash}, nil).Once()
			},
			wantReason: auditReasonUnknownCode,
		},
		{
			// The lookup succeeded here, so the entry names the user: that is what lets an
			// administrator see whose link is being replayed late.
			name: "an expired code",
			arrange: func(t *testing.T, database *mocks_data.Database) {
				user, codeHash := userWithCode(t, 42, code, time.Now().UTC().Add(-6*time.Minute))
				database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), codeHash).
					Return(user, nil).Once()
			},
			wantReason: auditReasonCodeExpired,
			wantUserId: 42,
		},
	}

	for _, tc := range rejections {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_audit.NewAuditLogger(t)
			store := newMarkerTestStore()

			tc.arrange(t, database)
			expectAuditFailedCode(auditLogger, tc.wantReason, tc.wantUserId)
			expectRenderedCodeInvalid(httpHelper, 0)

			handler := HandleResetPasswordGet(httpHelper, store, database, auditLogger)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, linkFollowedRequest(code))

			assert.NotEqual(t, http.StatusSeeOther, rr.Code, "a refused code must not redirect")

			_, rejection, err := GetLinkMarker(store, requestCarrying(t, rr), LinkMarkerFlowResetPassword)
			require.NoError(t, err)
			assert.Equal(t, LinkMarkerMissing, rejection, "a refused code must leave no marker")

			httpHelper.AssertExpectations(t)
			database.AssertExpectations(t)
			auditLogger.AssertExpectations(t)
		})
	}
}

// The wrong-account credential write, closed at its source. One session holds one marker and
// the form names nothing about the marker that rendered it, so a second link followed while
// one is live is refused rather than allowed to retarget a form already on screen. Without
// this the password typed for the first account is written into the second (#112 decision 13).
func TestHandleResetPasswordGet_SecondLinkWhileOneIsInFlight(t *testing.T) {
	const secondCode = "the-second-links-code"

	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	store := newMarkerTestStore()

	// The second link is entirely valid on its own: it is refused for the marker it would
	// have replaced, not for anything wrong with it.
	secondUser, secondHash := userWithCode(t, 99, secondCode, time.Now().UTC().Add(-time.Minute))
	database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), secondHash).Return(secondUser, nil).Once()

	// The entry names the link that was refused, which did resolve. The account holding the
	// live marker is not in the payload.
	expectAuditFailedCode(auditLogger, string(LinkMarkerContinuationInFlight), 99)
	expectRenderedCodeInvalid(httpHelper, 0)

	req := withMarker(t, store, linkFollowedRequest(secondCode), LinkMarkerFlowResetPassword, 42, "the-first-hash")

	handler := HandleResetPasswordGet(httpHelper, store, database, auditLogger)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.NotEqual(t, http.StatusSeeOther, rr.Code, "a refused second link must not redirect")

	// The first continuation survives untouched, so the form on screen still writes into the
	// account whose link produced it.
	marker, rejection, err := GetLinkMarker(store, nextBrowserRequest(t, req, rr), LinkMarkerFlowResetPassword)
	require.NoError(t, err)
	require.Empty(t, rejection)
	require.NotNil(t, marker)
	assert.Equal(t, "the-first-hash", marker.CodeHash)
	assert.Equal(t, int64(42), marker.Id)

	httpHelper.AssertExpectations(t)
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

// The same refusal against a live marker of the OTHER flow. Scoping the rule to one flow
// left a bridge: a wrong-flow marker is refused by every consuming step, so one
// replacement is harmless, but replacing an activation marker over a live reset one and
// then a reset marker over that puts the slot back into the reset flow naming an account
// the rendered form knows nothing about (#112 decision 14).
func TestHandleResetPasswordGet_SecondLinkWhileAnActivationIsInFlight(t *testing.T) {
	const secondCode = "the-second-links-code"

	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	store := newMarkerTestStore()

	secondUser, secondHash := userWithCode(t, 99, secondCode, time.Now().UTC().Add(-time.Minute))
	database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), secondHash).Return(secondUser, nil).Once()

	expectAuditFailedCode(auditLogger, string(LinkMarkerContinuationInFlight), 99)
	expectRenderedCodeInvalid(httpHelper, 0)

	req := withMarker(t, store, linkFollowedRequest(secondCode), LinkMarkerFlowAccountActivate, 7, "the-activation-hash")

	handler := HandleResetPasswordGet(httpHelper, store, database, auditLogger)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.NotEqual(t, http.StatusSeeOther, rr.Code, "a refused second link must not redirect")

	marker, rejection, err := GetLinkMarker(store, nextBrowserRequest(t, req, rr), LinkMarkerFlowAccountActivate)
	require.NoError(t, err)
	require.Empty(t, rejection)
	require.NotNil(t, marker)
	assert.Equal(t, "the-activation-hash", marker.CodeHash,
		"the activation continuation must still own the session")

	httpHelper.AssertExpectations(t)
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

// The code's own lifetime is enforced on the first hop and nowhere else, so the boundary
// belongs here. The two steps after the redirect are bounded by the marker's fresh window
// instead (#112 decision 7).
func TestHandleResetPasswordGet_LifetimeBoundary(t *testing.T) {
	const code = "the-emitted-code"

	t.Run("just inside the lifetime is accepted", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		store := newMarkerTestStore()

		user, codeHash := userWithCode(t, 1, code,
			time.Now().UTC().Add(-forgotPasswordCodeLifetime+30*time.Second))
		database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), codeHash).Return(user, nil).Once()

		handler := HandleResetPasswordGet(httpHelper, store, database, auditLogger)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, linkFollowedRequest(code))

		assert.Equal(t, http.StatusSeeOther, rr.Code)
	})

	t.Run("just outside the lifetime is refused", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		store := newMarkerTestStore()

		user, codeHash := userWithCode(t, 1, code,
			time.Now().UTC().Add(-forgotPasswordCodeLifetime-30*time.Second))
		database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), codeHash).Return(user, nil).Once()
		expectAuditFailedCode(auditLogger, auditReasonCodeExpired, 1)
		expectRenderedCodeInvalid(httpHelper, 0)

		handler := HandleResetPasswordGet(httpHelper, store, database, auditLogger)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, linkFollowedRequest(code))

		assert.NotEqual(t, http.StatusSeeOther, rr.Code)
		httpHelper.AssertExpectations(t)
	})
}

// =============================================================================
// The clean GET: where the 303 lands. No credential in the URL, only the marker,
// and the marker is not trusted on its own.
// =============================================================================

func TestHandleResetPasswordGet_Clean(t *testing.T) {
	const codeHash = "the-code-hash"

	t.Run("a live marker whose hash still resolves renders the form", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		store := newMarkerTestStore()

		database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), codeHash).
			Return(&models.User{Id: 1}, nil).Once()
		handler := HandleResetPasswordGet(httpHelper, store, database, auditLogger)
		req := withMarker(t, store, cleanGetRequest(), LinkMarkerFlowResetPassword, 1, codeHash)

		// The id the marker actually holds, so the assertion below cannot pass against a
		// handler binding some other value.
		marker, rejection, err := GetLinkMarker(store, req, LinkMarkerFlowResetPassword)
		require.NoError(t, err)
		require.Empty(t, rejection)
		require.NotEmpty(t, marker.ContinuationId)

		httpHelper.On("RenderTemplate",
			mock.Anything, mock.Anything,
			"/layouts/auth_layout.html", "/reset_password.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				invalid, ok := data["codeInvalidOrExpired"].(bool)
				if ok && invalid {
					return false
				}
				// The form must carry the continuation back, or every submission of it is
				// refused by the check the POST applies.
				return data["continuationId"] == marker.ContinuationId
			}),
		).Return(nil).Once()

		handler.ServeHTTP(httptest.NewRecorder(), req)

		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	// Each of these is audited under the reason GetLinkMarker itself reported, so the audit
	// vocabulary and the control flow cannot drift apart.
	t.Run("no marker at all", func(t *testing.T) {
		assertCleanGetRefused(t, string(LinkMarkerMissing), func(t *testing.T, store sessions.Store,
			database *mocks_data.Database) *http.Request {
			return cleanGetRequest()
		})
	})

	t.Run("a marker left by the activation flow", func(t *testing.T) {
		assertCleanGetRefused(t, string(LinkMarkerWrongFlow), func(t *testing.T, store sessions.Store,
			database *mocks_data.Database) *http.Request {
			return withMarker(t, store, cleanGetRequest(), LinkMarkerFlowAccountActivate, 7, codeHash)
		})
	})

	t.Run("a marker past its window", func(t *testing.T) {
		assertCleanGetRefused(t, string(LinkMarkerExpired), func(t *testing.T, store sessions.Store,
			database *mocks_data.Database) *http.Request {
			return withRawMarker(t, store, cleanGetRequest(),
				expiredMarkerJSON(t, LinkMarkerFlowResetPassword, 1, codeHash))
		})
	})

	// The replay case, at the unit tier: a marker that is still live but whose code hash is
	// no longer outstanding. That is what a captured cookie looks like after the reset
	// completed, after a newer code was issued, or after any other password change.
	t.Run("a live marker whose hash no longer resolves", func(t *testing.T) {
		assertCleanGetRefused(t, auditReasonCodeNoLongerOutstanding, func(t *testing.T, store sessions.Store,
			database *mocks_data.Database) *http.Request {
			database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), codeHash).
				Return(nil, nil).Once()
			return withMarker(t, store, cleanGetRequest(), LinkMarkerFlowResetPassword, 1, codeHash)
		})
	})
}

func assertCleanGetRefused(t *testing.T, wantReason string,
	arrange func(t *testing.T, store sessions.Store, database *mocks_data.Database) *http.Request) {
	t.Helper()

	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	store := newMarkerTestStore()

	req := arrange(t, store, database)
	expectAuditFailedCode(auditLogger, wantReason, 0)
	expectRenderedCodeInvalid(httpHelper, 0)

	handler := HandleResetPasswordGet(httpHelper, store, database, auditLogger)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	httpHelper.AssertExpectations(t)
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

// =============================================================================
// Tests for HandleResetPasswordPost
//
// This is the handler that actually changes the password. The cases below cover
// the rejection paths first, because each one is what stands between a stale,
// replayed or forged marker and an account takeover.
// =============================================================================

// expectRenderedFormError matches a re-render of the form carrying a non-empty
// error message, without coupling the test to the localized text.
//
// It also requires the continuation id to come back, which is not incidental: a mistyped
// confirmation re-renders the form, and a re-render that dropped the hidden field would
// make the user's next submission refused with no way to recover but the emailed link.
func expectRenderedFormError(httpHelper *mocks_handlerhelpers.HttpHelper, wantContinuationId string) {
	httpHelper.On("RenderTemplate",
		mock.Anything,
		mock.Anything,
		"/layouts/auth_layout.html",
		"/reset_password.html",
		mock.MatchedBy(func(data map[string]interface{}) bool {
			msg, ok := data["error"].(string)
			return ok && msg != "" && data["continuationId"] == wantContinuationId
		}),
	).Return(nil).Once()
}

func TestHandleResetPasswordPost_PasswordFieldRejections(t *testing.T) {
	// None of these reach the database or the session, which NewDatabase(t) and the absent
	// marker between them enforce: a handler that read the marker first would have to be
	// given one.
	testCases := []struct {
		name                 string
		password             string
		passwordConfirmation string
		// inQuery puts both credential fields in the request target instead of the body,
		// which must be answered exactly as an empty submission is (#202).
		inQuery bool
		arrange func(passwordValidator *mocks_validators.PasswordValidator)
	}{
		{
			name:     "empty password",
			password: "", passwordConfirmation: "",
			arrange: func(passwordValidator *mocks_validators.PasswordValidator) {},
		},
		{
			name:     "confirmation mismatch",
			password: "Str0ngP4ss!", passwordConfirmation: "Different1!",
			arrange: func(passwordValidator *mocks_validators.PasswordValidator) {},
		},
		{
			name:     "the validator refuses the password",
			password: "weak", passwordConfirmation: "weak",
			arrange: func(passwordValidator *mocks_validators.PasswordValidator) {
				passwordValidator.On("ValidatePassword", mock.Anything, "weak").
					Return(errors.New("too weak")).Once()
			},
		},
		{
			// A password strong enough to pass the validator, submitted in the query
			// alone. It must be refused as absent, and the validator is given no
			// expectation, so reaching it fails the test on an unexpected call: nothing
			// downstream of the read ran, and no password was set (#202).
			name:     "the credentials are in the query alone",
			password: "Str0ngP4ss!", passwordConfirmation: "Str0ngP4ss!", inQuery: true,
			arrange: func(passwordValidator *mocks_validators.PasswordValidator) {},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			database := mocks_data.NewDatabase(t)
			passwordValidator := mocks_validators.NewPasswordValidator(t)
			auditLogger := mocks_audit.NewAuditLogger(t)
			store := newMarkerTestStore()

			const continuationId = "the-continuation-the-form-carried"

			tc.arrange(passwordValidator)
			expectRenderedFormError(httpHelper, continuationId)

			build := postResetRequest
			if tc.inQuery {
				build = postResetWithCredentialsInQuery
			}

			handler := HandleResetPasswordPost(httpHelper, store, database, passwordValidator, auditLogger)
			handler.ServeHTTP(httptest.NewRecorder(),
				build(tc.password, tc.passwordConfirmation, continuationId))

			httpHelper.AssertExpectations(t)
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything)
		})
	}
}

// Every rejection below must leave the password untouched. NewDatabase(t) fails
// the test on an unexpected call, so the absence of a write expectation is the
// assertion that nothing was written.
func TestHandleResetPasswordPost_MarkerRejectionsDoNotChangeThePassword(t *testing.T) {
	const codeHash = "the-code-hash"
	const newPassword = "Str0ngP4ss!"

	testCases := []struct {
		name string
		// wantReason is the cause recorded in the audit entry. The response is the
		// same either way, so this is the only place the difference shows.
		wantReason string
		// wantUserId is 0 where nothing about the request established an account, and the
		// resolved id where the marker did resolve one before the rejection.
		wantUserId int64
		arrange    func(t *testing.T, store sessions.Store, database *mocks_data.Database) *http.Request
	}{
		{
			name:       "no marker at all",
			wantReason: string(LinkMarkerMissing),
			arrange: func(t *testing.T, store sessions.Store, database *mocks_data.Database) *http.Request {
				return postResetRequest(newPassword, newPassword, "")
			},
		},
		{
			name:       "a marker left by the activation flow",
			wantReason: string(LinkMarkerWrongFlow),
			arrange: func(t *testing.T, store sessions.Store, database *mocks_data.Database) *http.Request {
				return postWithMarker(t, store, newPassword, newPassword,
					LinkMarkerFlowAccountActivate, 7, codeHash)
			},
		},
		{
			name:       "a marker past its window",
			wantReason: string(LinkMarkerExpired),
			arrange: func(t *testing.T, store sessions.Store, database *mocks_data.Database) *http.Request {
				return withRawMarker(t, store, postResetRequest(newPassword, newPassword, ""),
					expiredMarkerJSON(t, LinkMarkerFlowResetPassword, 1, codeHash))
			},
		},
		{
			name:       "a live marker whose hash no longer resolves",
			wantReason: auditReasonCodeNoLongerOutstanding,
			arrange: func(t *testing.T, store sessions.Store, database *mocks_data.Database) *http.Request {
				database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), codeHash).
					Return(nil, nil).Once()
				return postWithMarker(t, store, newPassword, newPassword,
					LinkMarkerFlowResetPassword, 1, codeHash)
			},
		},
		// The retarget the continuation id exists for, and the reason no rule about
		// WRITING the marker can close it: the session legitimately holds a live marker
		// naming a different account, because the one that rendered this form expired,
		// completed, or lost a race, and the form is still on screen posting to the
		// identical clean URL (#112).
		{
			name:       "the form names a continuation the session has moved on from",
			wantReason: auditReasonContinuationMismatch,
			wantUserId: 1,
			arrange: func(t *testing.T, store sessions.Store, database *mocks_data.Database) *http.Request {
				database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), codeHash).
					Return(&models.User{Id: 1}, nil).Once()
				return withMarker(t, store,
					postResetRequest(newPassword, newPassword, "a-continuation-that-is-gone"),
					LinkMarkerFlowResetPassword, 1, codeHash)
			},
		},
		{
			name:       "the form names no continuation at all",
			wantReason: auditReasonContinuationMismatch,
			wantUserId: 1,
			arrange: func(t *testing.T, store sessions.Store, database *mocks_data.Database) *http.Request {
				database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), codeHash).
					Return(&models.User{Id: 1}, nil).Once()
				return withMarker(t, store, postResetRequest(newPassword, newPassword, ""),
					LinkMarkerFlowResetPassword, 1, codeHash)
			},
		},
		// The live id, correct in every respect but its source: in the request target
		// rather than the body, with the body carrying none. r.FormValue would merge the
		// query behind the body and pass the gate on it, so a link's continuation could be
		// driven from a URL again (#202, decision 3).
		{
			name:       "the form names the live continuation in the query alone",
			wantReason: auditReasonContinuationMismatch,
			wantUserId: 1,
			arrange: func(t *testing.T, store sessions.Store, database *mocks_data.Database) *http.Request {
				database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), codeHash).
					Return(&models.User{Id: 1}, nil).Once()
				return postWithMarkerContinuationInQuery(t, store, newPassword, newPassword,
					LinkMarkerFlowResetPassword, 1, codeHash)
			},
		},
		// A marker carrying no id is what a cookie written by an older binary looks like.
		// Two empty strings compare equal, so this is the case that would fail OPEN if the
		// check were a bare comparison.
		{
			name:       "the marker itself carries no continuation id",
			wantReason: auditReasonContinuationMismatch,
			wantUserId: 1,
			arrange: func(t *testing.T, store sessions.Store, database *mocks_data.Database) *http.Request {
				database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), codeHash).
					Return(&models.User{Id: 1}, nil).Once()
				return withRawMarker(t, store, postResetRequest(newPassword, newPassword, ""),
					marshalMarker(t, &LinkMarker{
						Flow:      LinkMarkerFlowResetPassword,
						Id:        1,
						CodeHash:  codeHash,
						ExpiresAt: time.Now().UTC().Add(linkMarkerLifetime),
					}))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			database := mocks_data.NewDatabase(t)
			passwordValidator := mocks_validators.NewPasswordValidator(t)
			auditLogger := mocks_audit.NewAuditLogger(t)
			store := newMarkerTestStore()

			passwordValidator.On("ValidatePassword", mock.Anything, newPassword).Return(nil).Once()
			req := tc.arrange(t, store, database)
			expectAuditFailedCode(auditLogger, tc.wantReason, tc.wantUserId)
			expectRenderedCodeInvalid(httpHelper, http.StatusBadRequest)

			handler := HandleResetPasswordPost(httpHelper, store, database, passwordValidator, auditLogger)
			handler.ServeHTTP(httptest.NewRecorder(), req)

			httpHelper.AssertExpectations(t)
			database.AssertExpectations(t)
			auditLogger.AssertExpectations(t)
			database.AssertNotCalled(t, "BeginTransaction")
		})
	}
}

func TestHandleResetPasswordPost_HappyPath(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)
	passwordValidator := mocks_validators.NewPasswordValidator(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	store := newMarkerTestStore()

	const codeHash = "the-code-hash"
	const newPassword = "Str0ngP4ss!"

	user := &models.User{Id: 1, Email: "test@example.com", PasswordHash: "the-previous-hash"}

	passwordValidator.On("ValidatePassword", mock.Anything, newPassword).Return(nil).Once()
	database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), codeHash).Return(user, nil).Once()

	var savedHash string
	// The claim's predicate is the marker's own hash, which is what refuses a replay: a
	// second call with the same hash matches no row once the first cleared it.
	database.On("TryConsumeForgotPasswordCode", revokeTx, int64(1), codeHash, mock.Anything).
		Run(func(args mock.Arguments) {
			savedHash = args.Get(3).(string)
		}).Return(true, nil).Once()
	stubRevocationSweepTx(database, 1, 4)

	auditLogger.On("Log", constants.AuditRevokedUserAuthState, mock.Anything).Return().Once()

	httpHelper.On("RenderTemplate",
		mock.Anything,
		mock.Anything,
		"/layouts/auth_layout.html",
		"/reset_password.html",
		mock.MatchedBy(func(data map[string]interface{}) bool {
			done, ok := data["passwordReset"].(bool)
			return ok && done
		}),
	).Return(nil).Once()

	handler := HandleResetPasswordPost(httpHelper, store, database, passwordValidator, auditLogger)
	rr := httptest.NewRecorder()
	req := postWithMarker(t, store, newPassword, newPassword,
		LinkMarkerFlowResetPassword, 1, codeHash)
	handler.ServeHTTP(rr, req)

	httpHelper.AssertExpectations(t)
	database.AssertExpectations(t)

	assert.NotEmpty(t, savedHash)
	assert.NotEqual(t, "the-previous-hash", savedHash, "the password hash must be replaced")
	assert.True(t, hashutil.VerifyPasswordHash(savedHash, newPassword),
		"the stored hash must verify against the new password")

	// The browser's own copy of the marker is dropped. Hygiene rather than the boundary:
	// what refuses a captured copy is the claim above, which the integration tier observes
	// with a real cookie jar. Read through nextBrowserRequest so this cannot pass against a
	// handler that simply never touched the session.
	_, rejection, err := GetLinkMarker(store, nextBrowserRequest(t, req, rr), LinkMarkerFlowResetPassword)
	require.NoError(t, err)
	assert.Equal(t, LinkMarkerMissing, rejection)

	// The narrow conditional write is the only one: a full-row update would undo a
	// concurrent admin disable (#106 decision 14).
	database.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "SetUserPasswordHash", mock.Anything, mock.Anything, mock.Anything)
}

// The claim matching no row is the replay and double-submit case, and it is NOT a server
// fault: the whole transaction rolls back, including the revocation sweep, and the caller
// gets the same indistinguishable rejection every other bad link gets.
func TestHandleResetPasswordPost_ClaimLost(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)
	passwordValidator := mocks_validators.NewPasswordValidator(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	store := newMarkerTestStore()

	const codeHash = "the-code-hash"
	const newPassword = "Str0ngP4ss!"

	passwordValidator.On("ValidatePassword", mock.Anything, newPassword).Return(nil).Once()
	database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), codeHash).
		Return(&models.User{Id: 1}, nil).Once()
	database.On("BeginTransaction").Return(revokeTx, nil).Once()
	database.On("TryConsumeForgotPasswordCode", revokeTx, int64(1), codeHash, mock.Anything).
		Return(false, nil).Once()
	database.On("RollbackTransaction", revokeTx).Return(nil).Once()

	// The lookup succeeded, so the entry names the user.
	expectAuditFailedCode(auditLogger, auditReasonClaimLost, 1)
	expectRenderedCodeInvalid(httpHelper, http.StatusBadRequest)

	handler := HandleResetPasswordPost(httpHelper, store, database, passwordValidator, auditLogger)
	handler.ServeHTTP(httptest.NewRecorder(),
		postWithMarker(t, store, newPassword, newPassword,
			LinkMarkerFlowResetPassword, 1, codeHash))

	httpHelper.AssertExpectations(t)
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)

	// Nothing committed, and no sweep started: a reset that wrote no password must not
	// terminate the user's sessions either.
	database.AssertNotCalled(t, "CommitTransaction", mock.Anything)
	database.AssertNotCalled(t, "IncrementUserAuthStateGeneration", mock.Anything, mock.Anything)
	// And it is not a 500: a lost claim is an ordinary outcome, not a fault.
	httpHelper.AssertNotCalled(t, "InternalServerError", mock.Anything, mock.Anything, mock.Anything)
}

// TestHandleResetPasswordPost_ClaimFails: the credential write itself errors inside the
// transaction. The sweep must never start, the transaction must roll back rather than commit,
// and no audit event may be emitted (#106 finding 26).
func TestHandleResetPasswordPost_ClaimFails(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)
	passwordValidator := mocks_validators.NewPasswordValidator(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	store := newMarkerTestStore()

	const codeHash = "the-code-hash"

	passwordValidator.On("ValidatePassword", mock.Anything, "Str0ngP4ss!").Return(nil).Once()
	database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), codeHash).
		Return(&models.User{Id: 1}, nil).Once()
	database.On("BeginTransaction").Return(revokeTx, nil).Once()
	database.On("TryConsumeForgotPasswordCode", revokeTx, int64(1), codeHash, mock.Anything).
		Return(false, errors.New("update failed")).Once()
	database.On("RollbackTransaction", revokeTx).Return(nil).Once()
	httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Return().Once()

	handler := HandleResetPasswordPost(httpHelper, store, database, passwordValidator, auditLogger)
	handler.ServeHTTP(httptest.NewRecorder(),
		postWithMarker(t, store, "Str0ngP4ss!", "Str0ngP4ss!",
			LinkMarkerFlowResetPassword, 1, codeHash))

	httpHelper.AssertExpectations(t)
	database.AssertExpectations(t)

	// Rolled back, not committed. The strict mock already fails on an unstubbed call, so these
	// restate the two that matter most explicitly, because a passing test here with a silently
	// committed transaction would be the worst outcome: a changed password with the old
	// sessions intact.
	database.AssertNotCalled(t, "CommitTransaction", mock.Anything)
	database.AssertNotCalled(t, "IncrementUserAuthStateGeneration", mock.Anything, mock.Anything)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything)
}

// TestHandleResetPasswordPost_TransactionFailureHandling: the credential write succeeds and
// something after it fails, which is the case finding 26 singles out because it is the one where a
// partially applied change is possible. Two variants failing at each of the sweep's two phases,
// and a third where the commit itself fails.
//
// Named for transaction FAILURE HANDLING rather than for rolling back, deliberately: only the first
// two variants roll back, and a name promising rollback for all three would contradict finding 36
// from inside the file it applies to.
//
// WHAT THE FIRST TWO PROVE: nothing is left half applied, because the deferred rollback discards
// the transaction, and no audit event claims a revocation that did not survive.
//
// WHAT THE THIRD PROVES, AND WHAT IT CANNOT. The commit-failure row asserts the HANDLER's
// behaviour: a 500 to the caller and no audit event. It does NOT establish that the transaction
// did not durably commit, and no mock could. `database/sql` gives no such guarantee: a Commit
// returning an error may mean the server committed and the client never found out, and the
// rollback this test stubs as succeeding cannot undo that. The mock models
// "Commit fails, Rollback succeeds" because that is the shape the code takes, not because the
// pair implies the write was undone. See the contract note on RevokeUserAuthStateTx.
func TestHandleResetPasswordPost_TransactionFailureHandling(t *testing.T) {
	const codeHash = "the-code-hash"
	const newPassword = "Str0ngP4ss!"

	for _, tc := range []struct {
		label string
		// arrange registers the sweep calls up to and including the failure.
		arrange func(database *mocks_data.Database)
	}{
		{
			// Discovery phase: nothing has been swept yet, but the generation HAS been
			// advanced, so a commit here would lock the user out of every session while
			// leaving refresh tokens unrevoked.
			label: "sweep fails during discovery",
			arrange: func(database *mocks_data.Database) {
				database.On("IncrementUserAuthStateGeneration", revokeTx, int64(1)).
					Return(int64(4), nil).Once()
				database.On("GetRefreshTokensByUserId", revokeTx, int64(1)).
					Return(nil, errors.New("discovery failed")).Once()
			},
		},
		{
			// Revocation phase: one token is already written revoked. A commit here would
			// revoke a subset, which is the half-applied state decision 5 exists to prevent.
			label: "sweep fails midway through revocation",
			arrange: func(database *mocks_data.Database) {
				first := &models.RefreshToken{Id: 1, RefreshTokenJti: "rt-1"}
				second := &models.RefreshToken{Id: 2, RefreshTokenJti: "rt-2"}
				database.On("IncrementUserAuthStateGeneration", revokeTx, int64(1)).
					Return(int64(4), nil).Once()
				database.On("GetRefreshTokensByUserId", revokeTx, int64(1)).
					Return([]*models.RefreshToken{first, second}, nil).Once()
				database.On("UpdateRefreshToken", revokeTx, first).Return(nil).Once()
				database.On("UpdateRefreshToken", revokeTx, second).
					Return(errors.New("revoke failed")).Once()
			},
		},
		{
			// The commit itself fails. Everything succeeded up to that point, so this is the
			// variant most likely to emit a false audit record. The durable outcome here is
			// indeterminate by nature; what is asserted is the handler's response and the
			// absence of an audit event, not that the write was undone.
			label: "commit fails after a complete sweep",
			arrange: func(database *mocks_data.Database) {
				database.On("IncrementUserAuthStateGeneration", revokeTx, int64(1)).
					Return(int64(4), nil).Once()
				database.On("GetRefreshTokensByUserId", revokeTx, int64(1)).
					Return([]*models.RefreshToken{}, nil).Once()
				database.On("PromoteRefreshTokenGenerations", revokeTx, []int64{}, int64(4)).
					Return(nil).Once()
				database.On("GetUserSessionsByUserId", revokeTx, int64(1)).
					Return([]models.UserSession{}, nil).Once()
				database.On("CommitTransaction", revokeTx).
					Return(errors.New("commit failed")).Once()
			},
		},
	} {
		t.Run(tc.label, func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			database := mocks_data.NewDatabase(t)
			passwordValidator := mocks_validators.NewPasswordValidator(t)
			auditLogger := mocks_audit.NewAuditLogger(t)
			store := newMarkerTestStore()

			passwordValidator.On("ValidatePassword", mock.Anything, newPassword).Return(nil).Once()
			database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), codeHash).
				Return(&models.User{Id: 1}, nil).Once()
			database.On("BeginTransaction").Return(revokeTx, nil).Once()
			database.On("TryConsumeForgotPasswordCode", revokeTx, int64(1), codeHash, mock.Anything).
				Return(true, nil).Once()
			tc.arrange(database)
			database.On("RollbackTransaction", revokeTx).Return(nil).Once()
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).
				Return().Once()

			handler := HandleResetPasswordPost(httpHelper, store, database, passwordValidator, auditLogger)
			handler.ServeHTTP(httptest.NewRecorder(),
				postWithMarker(t, store, newPassword, newPassword,
					LinkMarkerFlowResetPassword, 1, codeHash))

			httpHelper.AssertExpectations(t)
			database.AssertExpectations(t)

			// No audit event at all, on any of the three. This is the assertion that matters:
			// AuditLogger.Log takes no transaction, so an event emitted here would be a
			// permanent record of a revocation the caller was told had failed (decision 5).
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything)
			// And the success template is never rendered, so the caller is not told the
			// operation succeeded. This says nothing about the durable outcome: on the
			// commit-failure variant the write may in fact have applied (finding 36).
			httpHelper.AssertNotCalled(t, "RenderTemplate", mock.Anything, mock.Anything,
				mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// isForgotPasswordCodeExpired is the rule the first hop consults, so it is
// worth pinning directly as well as through the handler.
func TestIsForgotPasswordCodeExpired(t *testing.T) {
	testCases := []struct {
		name      string
		issuedAt  sql.NullTime
		wantExpir bool
	}{
		{"just issued", sql.NullTime{Time: time.Now().UTC(), Valid: true}, false},
		{"one minute old", sql.NullTime{Time: time.Now().UTC().Add(-time.Minute), Valid: true}, false},
		{"just inside the lifetime", sql.NullTime{Time: time.Now().UTC().Add(-forgotPasswordCodeLifetime + 30*time.Second), Valid: true}, false},
		{"just outside the lifetime", sql.NullTime{Time: time.Now().UTC().Add(-forgotPasswordCodeLifetime - time.Second), Valid: true}, true},
		{"an hour old", sql.NullTime{Time: time.Now().UTC().Add(-time.Hour), Valid: true}, true},
		{"never issued", sql.NullTime{Valid: false}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			user := &models.User{ForgotPasswordCodeIssuedAt: tc.issuedAt}

			assert.Equal(t, tc.wantExpir, isForgotPasswordCodeExpired(user))
		})
	}
}

// =============================================================================
// Response indistinguishability
//
// The reset endpoints must not reveal whether an email address has an account.
// An attacker can trigger POST /forgot-password for a target address (which
// correctly reveals nothing) and then probe /reset-password with a guessed code:
// if a known address answered differently from an unknown one, that difference is
// an account-existence oracle. Previously it was, because an unknown address and
// a user with no pending code both produced a 500 error page while a known
// address with a pending code produced the form.
//
// These tests capture the response for each condition and assert they are the
// same, so the oracle cannot reappear.
// =============================================================================

// captureResetRender records the bind map passed to RenderTemplate, along with
// which template was used.
func captureResetRender(t *testing.T, httpHelper *mocks_handlerhelpers.HttpHelper) *map[string]interface{} {
	t.Helper()
	captured := new(map[string]interface{})
	httpHelper.On("RenderTemplate",
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	).Run(func(args mock.Arguments) {
		*captured = args.Get(4).(map[string]interface{})
	}).Return(nil).Once()
	return captured
}

func TestResetPassword_LinkFailuresAreIndistinguishable(t *testing.T) {
	const requestCode = "the-emitted-code"
	const codeHash = "the-code-hash"
	const newPassword = "Str0ngP4ss!"

	hashOfRequestCode, err := hashutil.HashString(requestCode)
	require.NoError(t, err)

	// Every scenario below is a condition attributable to the link, across both
	// handlers and across all three hops. All must yield byte-identical responses.
	scenarios := []struct {
		name string
		// handler groups the scenario, because the two handlers deliberately use
		// different statuses: what must match is every branch WITHIN a handler.
		handler    string
		wantStatus interface{} // nil when no _httpStatus is set
		setup      func(t *testing.T) (*map[string]interface{}, func())
	}{
		{
			name:    "GET, a code matching no outstanding reset",
			handler: "GET",
			setup: func(t *testing.T) (*map[string]interface{}, func()) {
				httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
				database := mocks_data.NewDatabase(t)
				auditLogger := mocks_audit.NewAuditLogger(t)
				store := newMarkerTestStore()
				database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), hashOfRequestCode).
					Return(nil, nil).Once()
				expectAuditFailedCode(auditLogger, auditReasonUnknownCode, 0)
				bind := captureResetRender(t, httpHelper)
				handler := HandleResetPasswordGet(httpHelper, store, database, auditLogger)
				req := linkFollowedRequest(requestCode)
				return bind, func() { handler.ServeHTTP(httptest.NewRecorder(), req) }
			},
		},
		{
			name:    "GET, an expired code",
			handler: "GET",
			setup: func(t *testing.T) (*map[string]interface{}, func()) {
				httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
				database := mocks_data.NewDatabase(t)
				auditLogger := mocks_audit.NewAuditLogger(t)
				store := newMarkerTestStore()
				user, hash := userWithCode(t, 1, requestCode, time.Now().UTC().Add(-time.Hour))
				database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), hash).
					Return(user, nil).Once()
				expectAuditFailedCode(auditLogger, auditReasonCodeExpired, 1)
				bind := captureResetRender(t, httpHelper)
				handler := HandleResetPasswordGet(httpHelper, store, database, auditLogger)
				req := linkFollowedRequest(requestCode)
				return bind, func() { handler.ServeHTTP(httptest.NewRecorder(), req) }
			},
		},
		{
			name:    "GET, no marker on the clean URL",
			handler: "GET",
			setup: func(t *testing.T) (*map[string]interface{}, func()) {
				httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
				database := mocks_data.NewDatabase(t)
				auditLogger := mocks_audit.NewAuditLogger(t)
				store := newMarkerTestStore()
				expectAuditFailedCode(auditLogger, string(LinkMarkerMissing), 0)
				bind := captureResetRender(t, httpHelper)
				handler := HandleResetPasswordGet(httpHelper, store, database, auditLogger)
				req := cleanGetRequest()
				return bind, func() { handler.ServeHTTP(httptest.NewRecorder(), req) }
			},
		},
		{
			name:    "GET, a marker whose hash no longer resolves",
			handler: "GET",
			setup: func(t *testing.T) (*map[string]interface{}, func()) {
				httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
				database := mocks_data.NewDatabase(t)
				auditLogger := mocks_audit.NewAuditLogger(t)
				store := newMarkerTestStore()
				database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), codeHash).
					Return(nil, nil).Once()
				expectAuditFailedCode(auditLogger, auditReasonCodeNoLongerOutstanding, 0)
				bind := captureResetRender(t, httpHelper)
				handler := HandleResetPasswordGet(httpHelper, store, database, auditLogger)
				req := withMarker(t, store, cleanGetRequest(), LinkMarkerFlowResetPassword, 1, codeHash)
				return bind, func() { handler.ServeHTTP(httptest.NewRecorder(), req) }
			},
		},
		{
			name:       "POST, no marker",
			handler:    "POST",
			wantStatus: http.StatusBadRequest,
			setup: func(t *testing.T) (*map[string]interface{}, func()) {
				httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
				database := mocks_data.NewDatabase(t)
				passwordValidator := mocks_validators.NewPasswordValidator(t)
				auditLogger := mocks_audit.NewAuditLogger(t)
				store := newMarkerTestStore()
				passwordValidator.On("ValidatePassword", mock.Anything, newPassword).Return(nil).Once()
				expectAuditFailedCode(auditLogger, string(LinkMarkerMissing), 0)
				bind := captureResetRender(t, httpHelper)
				handler := HandleResetPasswordPost(httpHelper, store, database, passwordValidator, auditLogger)
				req := postResetRequest(newPassword, newPassword, "")
				return bind, func() { handler.ServeHTTP(httptest.NewRecorder(), req) }
			},
		},
		{
			name:       "POST, a marker whose hash no longer resolves",
			handler:    "POST",
			wantStatus: http.StatusBadRequest,
			setup: func(t *testing.T) (*map[string]interface{}, func()) {
				httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
				database := mocks_data.NewDatabase(t)
				passwordValidator := mocks_validators.NewPasswordValidator(t)
				auditLogger := mocks_audit.NewAuditLogger(t)
				store := newMarkerTestStore()
				passwordValidator.On("ValidatePassword", mock.Anything, newPassword).Return(nil).Once()
				database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), codeHash).
					Return(nil, nil).Once()
				expectAuditFailedCode(auditLogger, auditReasonCodeNoLongerOutstanding, 0)
				bind := captureResetRender(t, httpHelper)
				handler := HandleResetPasswordPost(httpHelper, store, database, passwordValidator, auditLogger)
				req := postWithMarker(t, store, newPassword, newPassword,
					LinkMarkerFlowResetPassword, 1, codeHash)
				return bind, func() { handler.ServeHTTP(httptest.NewRecorder(), req) }
			},
		},
		{
			name:       "POST, the form names another continuation",
			handler:    "POST",
			wantStatus: http.StatusBadRequest,
			setup: func(t *testing.T) (*map[string]interface{}, func()) {
				httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
				database := mocks_data.NewDatabase(t)
				passwordValidator := mocks_validators.NewPasswordValidator(t)
				auditLogger := mocks_audit.NewAuditLogger(t)
				store := newMarkerTestStore()
				passwordValidator.On("ValidatePassword", mock.Anything, newPassword).Return(nil).Once()
				database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), codeHash).
					Return(&models.User{Id: 1}, nil).Once()
				expectAuditFailedCode(auditLogger, auditReasonContinuationMismatch, 1)
				bind := captureResetRender(t, httpHelper)
				handler := HandleResetPasswordPost(httpHelper, store, database, passwordValidator, auditLogger)
				req := withMarker(t, store,
					postResetRequest(newPassword, newPassword, "a-continuation-that-is-gone"),
					LinkMarkerFlowResetPassword, 1, codeHash)
				return bind, func() { handler.ServeHTTP(httptest.NewRecorder(), req) }
			},
		},
		{
			name:       "POST, the claim was lost",
			handler:    "POST",
			wantStatus: http.StatusBadRequest,
			setup: func(t *testing.T) (*map[string]interface{}, func()) {
				httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
				database := mocks_data.NewDatabase(t)
				passwordValidator := mocks_validators.NewPasswordValidator(t)
				auditLogger := mocks_audit.NewAuditLogger(t)
				store := newMarkerTestStore()
				passwordValidator.On("ValidatePassword", mock.Anything, newPassword).Return(nil).Once()
				database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), codeHash).
					Return(&models.User{Id: 1}, nil).Once()
				database.On("BeginTransaction").Return(revokeTx, nil).Once()
				database.On("TryConsumeForgotPasswordCode", revokeTx, int64(1), codeHash, mock.Anything).
					Return(false, nil).Once()
				database.On("RollbackTransaction", revokeTx).Return(nil).Once()
				expectAuditFailedCode(auditLogger, auditReasonClaimLost, 1)
				bind := captureResetRender(t, httpHelper)
				handler := HandleResetPasswordPost(httpHelper, store, database, passwordValidator, auditLogger)
				req := postWithMarker(t, store, newPassword, newPassword,
					LinkMarkerFlowResetPassword, 1, codeHash)
				return bind, func() { handler.ServeHTTP(httptest.NewRecorder(), req) }
			},
		},
	}

	reference := map[string]map[string]interface{}{}
	referenceName := map[string]string{}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			bind, run := sc.setup(t)
			run()

			// Compared whole. Nothing in this bind varies between two requests any more, so
			// there is nothing to strip before the scenarios are held against each other.
			got := *bind
			assert.Equal(t, true, got["codeInvalidOrExpired"])
			assert.Equal(t, sc.wantStatus, got["_httpStatus"])

			if _, seen := reference[sc.handler]; !seen {
				reference[sc.handler], referenceName[sc.handler] = got, sc.name
				return
			}
			assert.Equal(t, reference[sc.handler], got,
				"%q must be indistinguishable from %q, otherwise it reveals whether the address has an account",
				sc.name, referenceName[sc.handler])
		})
	}
}

// A genuine server fault must stay a 500 with its stack trace, so real problems
// keep alerting instead of being hidden behind the friendly page.
func TestResetPassword_GenuineFaultsStayInternalServerErrors(t *testing.T) {
	const code = "the-emitted-code"

	t.Run("GET, stored code will not decrypt", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		store := newMarkerTestStore()

		codeHash, err := hashutil.HashString(code)
		require.NoError(t, err)
		user := &models.User{
			Id: 1, Email: "test@example.com",
			ForgotPasswordCodeEncrypted: []byte("not-valid-ciphertext"),
			ForgotPasswordCodeHash:      codeHash,
			ForgotPasswordCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC(), Valid: true},
		}
		database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), codeHash).Return(user, nil).Once()
		httpHelper.On("InternalServerError", mock.Anything, mock.Anything,
			mock.MatchedBy(func(err error) bool {
				return strings.Contains(err.Error(), "unable to decrypt forgot password code")
			}),
		).Return().Once()

		handler := HandleResetPasswordGet(httpHelper, store, database, auditLogger)
		handler.ServeHTTP(httptest.NewRecorder(), linkFollowedRequest(code))

		httpHelper.AssertExpectations(t)
	})

	t.Run("GET, database failure on the first hop", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		store := newMarkerTestStore()

		database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), mock.Anything).
			Return(nil, errors.New("database is down")).Once()
		httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Return().Once()

		handler := HandleResetPasswordGet(httpHelper, store, database, auditLogger)
		handler.ServeHTTP(httptest.NewRecorder(), linkFollowedRequest(code))

		httpHelper.AssertExpectations(t)
	})

	t.Run("GET, database failure on the clean hop", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		store := newMarkerTestStore()

		database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), "the-code-hash").
			Return(nil, errors.New("database is down")).Once()
		httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Return().Once()

		handler := HandleResetPasswordGet(httpHelper, store, database, auditLogger)
		handler.ServeHTTP(httptest.NewRecorder(),
			withMarker(t, store, cleanGetRequest(), LinkMarkerFlowResetPassword, 1, "the-code-hash"))

		httpHelper.AssertExpectations(t)
	})

	// A marker this process wrote and cannot read back is a fault in this process, not a bad
	// link: the session cookie is encrypted and signed, so nobody outside it can put one there.
	t.Run("GET, a corrupt marker", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		store := newMarkerTestStore()

		httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Return().Once()

		handler := HandleResetPasswordGet(httpHelper, store, database, auditLogger)
		handler.ServeHTTP(httptest.NewRecorder(),
			withRawMarker(t, store, cleanGetRequest(), "not json"))

		httpHelper.AssertExpectations(t)
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything)
	})

	// A session store that cannot be written is a fault too: proceeding would answer 303 to a
	// URL the marker never reached, and the user would land on an unexplained dead page.
	t.Run("GET, the marker cannot be saved", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		store := mocks_sessionstore.NewStore(t)

		user, codeHash := userWithCode(t, 1, code, time.Now().UTC())
		database.On("GetUserByForgotPasswordCodeHash", (*sql.Tx)(nil), codeHash).Return(user, nil).Once()
		store.On("Get", mock.Anything, constants.AuthServerSessionName).
			Return(nil, errors.New("session store is unavailable"))
		httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Return().Once()

		handler := HandleResetPasswordGet(httpHelper, store, database, auditLogger)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, linkFollowedRequest(code))

		assert.NotEqual(t, http.StatusSeeOther, rr.Code)
		httpHelper.AssertExpectations(t)
	})
}

// If rendering the invalid-or-expired page itself fails, that is a real fault and
// must surface as a 500 rather than a blank response.
func TestRenderResetPasswordCodeInvalid_RenderFailureFallsBackToInternalServerError(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	store := newMarkerTestStore()

	expectAuditFailedCode(auditLogger, string(LinkMarkerMissing), 0)
	httpHelper.On("RenderTemplate",
		mock.Anything, mock.Anything,
		"/layouts/auth_layout.html", "/reset_password.html", mock.Anything,
	).Return(errors.New("template blew up")).Once()
	httpHelper.On("InternalServerError", mock.Anything, mock.Anything,
		mock.MatchedBy(func(err error) bool { return err.Error() == "template blew up" }),
	).Return().Once()

	handler := HandleResetPasswordGet(httpHelper, store, database, auditLogger)
	handler.ServeHTTP(httptest.NewRecorder(), cleanGetRequest())

	httpHelper.AssertExpectations(t)
}

// The audit payload is what an administrator watching for probing reads, and #112 replaced
// every field in it. These pin the shape directly rather than only through the handlers.
func TestAuditFailedResetPasswordCode(t *testing.T) {
	capture := func(t *testing.T, r *http.Request, userId int64, reason string) map[string]interface{} {
		t.Helper()
		auditLogger := mocks_audit.NewAuditLogger(t)
		var captured map[string]interface{}
		auditLogger.On("Log", constants.AuditFailedResetPasswordCode, mock.Anything).
			Run(func(args mock.Arguments) {
				captured = args.Get(1).(map[string]interface{})
			}).Return().Once()

		auditFailedResetPasswordCode(auditLogger, r, userId, reason)
		return captured
	}

	t.Run("the client IP is always recorded and no address ever is", func(t *testing.T) {
		req := cleanGetRequest()
		req.RemoteAddr = "203.0.113.7:54321"

		details := capture(t, req, 0, auditReasonUnknownCode)

		assert.Equal(t, "203.0.113.7", details["ip"])
		assert.Equal(t, auditReasonUnknownCode, details["reason"])
		assert.NotContains(t, details, "email")
		assert.NotContains(t, details, "userId",
			"an unresolved lookup must leave the key absent rather than naming user 0")
	})

	t.Run("a resolved userId is recorded beside it", func(t *testing.T) {
		details := capture(t, cleanGetRequest(), 42, auditReasonCodeExpired)

		assert.Equal(t, int64(42), details["userId"])
		assert.NotContains(t, details, "email")
	})

	// MiddlewareRealIP resolves the address from a forwarded header in a proxied deployment,
	// so this function is still a sink for a value originating outside the process.
	t.Run("an oversized address is truncated", func(t *testing.T) {
		req := cleanGetRequest()
		req.RemoteAddr = strings.Repeat("a", 250)

		details := capture(t, req, 0, auditReasonUnknownCode)

		assert.Len(t, details["ip"], 100)
	})
}

// forgotPasswordCodeMatches is the comparison that decides whether an index hit is really
// the code that was issued, so it is pinned directly as well as through the handler. The
// point of the constant-time comparison is not observable from the outside, so what these
// cases guard is that the matching semantics stayed correct when it was introduced.
func TestForgotPasswordCodeMatches(t *testing.T) {
	testCases := []struct {
		name     string
		stored   string
		supplied string
		want     bool
	}{
		{"identical codes match", "abc123", "abc123", true},
		{"long identical codes match", strings.Repeat("a1B2", 8), strings.Repeat("a1B2", 8), true},
		{"different codes do not match", "abc123", "abc124", false},
		{"differing only in the last byte", "abc123", "abc12X", false},
		{"differing only in the first byte", "abc123", "Xbc123", false},
		{"a prefix does not match", "abc123", "abc", false},
		{"a longer supplied code does not match", "abc123", "abc1234", false},
		{"case matters", "abc123", "ABC123", false},
		{"empty supplied code does not match a stored one", "abc123", "", false},
		{"empty stored code does not match a supplied one", "", "abc123", false},
		{"two empty strings match", "", "", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, forgotPasswordCodeMatches(tc.stored, tc.supplied))
		})
	}
}
