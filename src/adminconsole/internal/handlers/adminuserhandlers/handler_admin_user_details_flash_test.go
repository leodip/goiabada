package adminuserhandlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	mocks_handlerhelpers "github.com/leodip/goiabada/adminconsole/internal/handlerhelpers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
)

// The user details page is the one handler in the tree that reads two flash keys behind a
// single save guard, `if savedSuccessfully || userCreated`, and that guard is a caller's
// decision the flash primitives cannot see: turned into `&&` it still compiles, still
// renders, and still shows the right notice on the request that flashed it -- but the
// consumption of a lone key is never saved, so that notice then shows on every reload for
// the rest of the session (#269).
//
// Two keys also make the argument order of SetFlash observable in a second way: a handler
// that reads the wrong key of the two binds a notice the user did not earn.

// flashStubApiClient answers the one call the details GET makes.
type flashStubApiClient struct {
	apiclient.ApiClient
}

func (flashStubApiClient) GetUserById(accessToken string, id int64) (*api.UserResponse, error) {
	return &api.UserResponse{Id: id, Email: "someone@example.com"}, nil
}

// newFlashTestStore is a real store over an in-memory backend, because a flash is only
// interesting once it has crossed a save and a load.
func newFlashTestStore() *sessionstore.ServerSideStore {
	store, err := sessionstore.NewServerSideStore(
		sessiontest.NewMemoryBackend(),
		constants.SessionKeyJwt,
		false,
		sessionstore.KeyPair{
			AuthenticationKey: []byte("12345678901234567890123456789012"),
			EncryptionKey:     []byte("abcdefghijklmnopqrstuvwxyz123456"),
		},
		nil,
	)
	if err != nil {
		// The keys are literals above and the derivation cannot fail on them, so this is
		// unreachable. Panicking rather than dropping it keeps it that way.
		panic(err)
	}
	return store
}

// detailsRequest builds the GET the handler expects: the userId route parameter chi would
// have matched, and the access token it reads out of the request context.
func detailsRequest() *http.Request {
	return handlertest.Request(http.MethodGet, "/admin/users/7/details",
		handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", "7"))
}

// flashInSession puts the named flashes into a stored session and returns the cookie that
// names it, which is what the handler that redirected here would have left the browser.
func flashInSession(t *testing.T, store *sessionstore.ServerSideStore, keys ...string) *http.Cookie {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	rec := httptest.NewRecorder()

	sess, err := store.Get(req, coreconstants.AdminConsoleSessionName)
	require.NoError(t, err)
	for _, key := range keys {
		sess.SetFlash(key, "true")
	}
	require.NoError(t, store.Save(req, rec, sess))

	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	return cookies[0]
}

// renderDetails runs the GET once against the given cookie and returns what it bound.
func renderDetails(t *testing.T, store *sessionstore.ServerSideStore,
	cookie *http.Cookie) (map[string]interface{}, *httptest.ResponseRecorder) {

	t.Helper()

	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_users_details.html").Once()

	req := detailsRequest()
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()

	HandleAdminUserDetailsGet(httpHelper, store, flashStubApiClient{}).ServeHTTP(rec, req)

	bind := handlertest.Bind(t, httpHelper)
	return bind, rec
}

func TestHandleAdminUserDetailsGet_TheTwoNoticesAreIndependentAndEachShowsOnce(t *testing.T) {
	testCases := []struct {
		name        string
		flashes     []string
		wantSaved   bool
		wantCreated bool
	}{
		{
			name: "neither key set",
		},
		{
			name:      "only savedSuccessfully",
			flashes:   []string{"savedSuccessfully"},
			wantSaved: true,
		},
		{
			name:        "only userCreated",
			flashes:     []string{"userCreated"},
			wantCreated: true,
		},
		{
			name:        "both keys",
			flashes:     []string{"savedSuccessfully", "userCreated"},
			wantSaved:   true,
			wantCreated: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := newFlashTestStore()

			var cookie *http.Cookie
			if len(tc.flashes) > 0 {
				cookie = flashInSession(t, store, tc.flashes...)
			}

			bind, rec := renderDetails(t, store, cookie)
			assert.Equal(t, tc.wantSaved, bind["savedSuccessfully"])
			assert.Equal(t, tc.wantCreated, bind["userCreated"])

			if cookie == nil {
				return
			}

			// The reload. Whichever notices showed must be gone, and gone because the
			// request above saved its consumption: a save guard that misses a lone key
			// leaves that key showing forever.
			next := cookie
			if saved := rec.Result().Cookies(); len(saved) > 0 {
				next = saved[0]
			}
			reloaded, _ := renderDetails(t, store, next)
			assert.Equal(t, false, reloaded["savedSuccessfully"], "on reload")
			assert.Equal(t, false, reloaded["userCreated"], "on reload")
		})
	}
}
