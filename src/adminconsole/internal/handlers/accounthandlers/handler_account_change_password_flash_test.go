package accounthandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	mocks_handler_helpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
)

// This file exists because the session store's own tests cannot see the 69 call sites that
// use the flash pair, and two of the three ways a rewritten call site can be wrong compile
// and pass everything else in the tree (#269).
//
// SetFlash(key, value) takes its arguments in the opposite order to the AddFlash(value, key)
// it replaced, and both are strings, so a reversed call is valid Go that stores "true" ->
// "savedSuccessfully" and reads nothing back. And consuming a flash is a change to the
// session that only persists if the handler saves it, which is a caller's `if` rather than
// the primitive's business, so a dropped save leaves the notice showing on every reload
// forever. Neither is visible to a test of SetFlash and TakeFlash themselves.
//
// One handler, deliberately, rather than 35 copies of one assertion: the shape is identical
// at every site, and the second shape worth covering -- two keys behind one save guard --
// lives in adminuserhandlers where the only such guard is.

// flashStubApiClient reports success on the one call the change-password POST makes.
type flashStubApiClient struct {
	apiclient.ApiClient
}

func (flashStubApiClient) UpdateAccountPassword(accessToken string,
	request *api.UpdateAccountPasswordRequest) (*models.User, error) {
	return &models.User{Id: 7}, nil
}

// newFlashTestStore is a real store over an in-memory backend. The flash has to cross a
// save and a load to be worth asserting on, and a mocked store would hand back whatever
// the test put in it, which is the assertion making itself true.
func newFlashTestStore() *sessionstore.ServerSideStore {
	return sessionstore.NewServerSideStore(
		sessionstore.NewMemoryBackend(),
		constants.SessionKeyJwt,
		false,
		[]byte("12345678901234567890123456789012"),
		[]byte("abcdefghijklmnopqrstuvwxyz123456"),
	)
}

// withJwtInfo puts the access token the handlers read out of the request context in place.
func withJwtInfo(req *http.Request) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo,
		oauth.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: testAccessToken}}))
}

// cookieJar is a browser's cookie jar: it keeps what a response set and keeps carrying it
// until a later response replaces it.
//
// Accumulating rather than reading one response's Set-Cookie is what makes the reload case
// below load bearing. A handler that consumed a flash and never saved the consumption sets
// no cookie at all, so a jar built from that one response would send the next request
// bare, that request would open a fresh session, and the assertion that the notice is gone
// would pass on a request that had no session to find it in. The bug would go unseen by the
// case written to catch it (#269).
type cookieJar struct {
	cookies map[string]*http.Cookie
}

func newCookieJar() *cookieJar {
	return &cookieJar{cookies: map[string]*http.Cookie{}}
}

// keep records whatever a response set.
func (j *cookieJar) keep(rr *httptest.ResponseRecorder) {
	for _, cookie := range rr.Result().Cookies() {
		j.cookies[cookie.Name] = cookie
	}
}

// send puts everything the jar holds onto a request.
func (j *cookieJar) send(req *http.Request) *http.Request {
	for _, cookie := range j.cookies {
		req.AddCookie(cookie)
	}
	return req
}

// TestHandleAccountChangePassword_TheNoticeShowsOnceAndThenStops drives the POST and two
// GETs on one cookie jar, which is the sequence a user performs: submit the form, read the
// notice, reload the page.
func TestHandleAccountChangePassword_TheNoticeShowsOnceAndThenStops(t *testing.T) {
	store := newFlashTestStore()

	// The POST: the API accepts the change, the handler flashes and redirects.
	postHelper := mocks_handler_helpers.NewHttpHelper(t)
	form := url.Values{
		"currentPassword":         {"P4ss!word"},
		"newPassword":             {"N3w!word"},
		"newPasswordConfirmation": {"N3w!word"},
	}
	postReq := withJwtInfo(httptest.NewRequest(http.MethodPost, "/account/change-password",
		strings.NewReader(form.Encode())))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postRec := httptest.NewRecorder()

	HandleAccountChangePasswordPost(postHelper, store, flashStubApiClient{}).
		ServeHTTP(postRec, postReq)

	require.Equal(t, http.StatusFound, postRec.Code,
		"a successful change redirects rather than rendering")

	jar := newCookieJar()
	jar.keep(postRec)
	require.NotEmpty(t, jar.cookies, "the POST must have named a session for the GET to find")

	// The first GET: the notice is there.
	firstHelper := mocks_handler_helpers.NewHttpHelper(t)
	firstHelper.On("RenderTemplate", mock.Anything, mock.Anything,
		"/layouts/menu_layout.html", "/account_change_password.html", mock.Anything).
		Return(nil).Once()
	firstRec := httptest.NewRecorder()
	firstReq := jar.send(withJwtInfo(
		httptest.NewRequest(http.MethodGet, "/account/change-password", nil)))

	HandleAccountChangePasswordGet(firstHelper, store, nil).ServeHTTP(firstRec, firstReq)
	jar.keep(firstRec)

	assert.Equal(t, true, bindOf(t, firstHelper)["savedSuccessfully"],
		"the notice the POST flashed must reach the page that renders it")

	// The second GET: it is gone, and gone because the first GET saved the consumption.
	secondHelper := mocks_handler_helpers.NewHttpHelper(t)
	secondHelper.On("RenderTemplate", mock.Anything, mock.Anything,
		"/layouts/menu_layout.html", "/account_change_password.html", mock.Anything).
		Return(nil).Once()
	secondReq := jar.send(withJwtInfo(
		httptest.NewRequest(http.MethodGet, "/account/change-password", nil)))

	HandleAccountChangePasswordGet(secondHelper, store, nil).
		ServeHTTP(httptest.NewRecorder(), secondReq)

	assert.Equal(t, false, bindOf(t, secondHelper)["savedSuccessfully"],
		"a reload must not show the notice again")
}

// TestHandleAccountChangePasswordGet_NoFlashIsNoNotice is the negative half: without it the
// case above is satisfied by a handler that binds true unconditionally.
func TestHandleAccountChangePasswordGet_NoFlashIsNoNotice(t *testing.T) {
	httpHelper := mocks_handler_helpers.NewHttpHelper(t)
	httpHelper.On("RenderTemplate", mock.Anything, mock.Anything,
		"/layouts/menu_layout.html", "/account_change_password.html", mock.Anything).
		Return(nil).Once()

	req := withJwtInfo(httptest.NewRequest(http.MethodGet, "/account/change-password", nil))

	HandleAccountChangePasswordGet(httpHelper, newFlashTestStore(), nil).
		ServeHTTP(httptest.NewRecorder(), req)

	assert.Equal(t, false, bindOf(t, httpHelper)["savedSuccessfully"])
}
