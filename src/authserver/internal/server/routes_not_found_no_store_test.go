package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// assertNoStore asserts the pair the server's no-store answers send, and no Expires beside it, on
// the header fields the answer was sent with: the recorder's snapshot taken when the status was
// written, not its live map, which a field set after the status still reaches.
func assertNoStore(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	sent := rr.Result().Header
	assert.Equal(t, []string{"no-store"}, sent.Values("Cache-Control"))
	assert.Equal(t, []string{"no-cache"}, sent.Values("Pragma"))
	assert.Empty(t, sent.Values("Expires"))
}

// Every "not found" a public resource outside the page branch answers is no-store, on GET and on
// HEAD: a client logo, a profile picture, each of a brand's four stylesheets and a brand asset, for
// each reason it is not found, and a static file that does not exist. A 404 is heuristically
// cacheable (RFC 9110 section 15.5.5), and a cache may keep one that names no lifetime as long as
// it chooses (RFC 9111 section 4.2.2), so "no logo" could outlive the upload of one (#825 decision
// 3). Each answer is the resource's own plain-text 404, not the 404 page, which is a page answer and
// no-store already. The strict database mock holds each request to the read its reason makes.
func TestRegisterRoutes_APublicResourceNotFoundIsNoStore(t *testing.T) {
	noClient := func(database *datamocks.Database) {
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "no-such-client").Return(nil, nil).Once()
	}
	noLogo := func(database *datamocks.Database) {
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "shop").
			Return(&record.Client{ID: 3, ClientIdentifier: "shop"}, nil).Once()
		database.On("GetClientLogoByClientID", mock.Anything, mock.Anything, int64(3)).Return(nil, nil).Once()
	}
	noUser := func(database *datamocks.Database) {
		database.On("GetUserBySubject", mock.Anything, mock.Anything, "no-such-subject").Return(nil, nil).Once()
	}
	noPicture := func(database *datamocks.Database) {
		database.On("GetUserBySubject", mock.Anything, mock.Anything, "plain-user").
			Return(&record.User{ID: 5, Subject: "plain-user"}, nil).Once()
		database.On("GetUserProfilePictureByUserID", mock.Anything, mock.Anything, int64(5)).Return(nil, nil).Once()
	}
	noBrand := func(database *datamocks.Database) {
		database.On("GetBrandByID", mock.Anything, mock.Anything, int64(99)).Return(nil, nil).Once()
	}
	noAsset := func(database *datamocks.Database) {
		database.On("GetBrandAssetByID", mock.Anything, mock.Anything, int64(99)).Return(nil, nil).Once()
	}
	nothing := func(*datamocks.Database) {}

	type notFound struct {
		name, target string
		expect       func(*datamocks.Database)
	}
	cases := []notFound{
		{"a client that does not exist", "/client/logo/no-such-client", noClient},
		{"a client with no logo", "/client/logo/shop", noLogo},
		{"a user that does not exist", "/userinfo/picture/no-such-subject", noUser},
		{"a user with no picture", "/userinfo/picture/plain-user", noPicture},
		{"an asset id that is not one", "/brand-assets/logo", nothing},
		{"an asset id that is not positive", "/brand-assets/0", nothing},
		{"an asset that does not exist", "/brand-assets/99", noAsset},
		{"a static file that does not exist", "/static/no-such-file.css", nothing},
		{"a static file that does not exist, asked by a fingerprint", "/static/no-such-file.css?v=0123456789ab", nothing},
		{"a static file below a file", "/static/main.css/inside", nothing},
		// The router matches the decoded /static/main.css, a file, but the escaped path does not
		// begin with /static, which the file server's prefix removal refuses.
		{"a static file whose prefix is escaped", "/st%61tic/main.css", nothing},
		{"a static file whose prefix is escaped, asked by a fingerprint", "/st%61tic/main.css?v=0123456789ab", nothing},
	}
	for _, stylesheet := range []string{"stylesheet.css", "colors.css", "safe-stylesheet.css", "safe-colors.css"} {
		cases = append(cases,
			notFound{"a brand id that is not one, " + stylesheet, "/brand/plum/" + stylesheet, nothing},
			notFound{"a brand id that is not positive, " + stylesheet, "/brand/-1/" + stylesheet, nothing},
			notFound{"a brand that does not exist, " + stylesheet, "/brand/99/" + stylesheet, noBrand},
		)
	}

	for _, answer := range cases {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			t.Run(answer.name+" "+method, func(t *testing.T) {
				database := newRoutingDatabase(t)
				answer.expect(database)
				s := newRoutingTestServer(t, database)

				rr := serveRouting(s, method, answer.target, nil)

				require.Equal(t, http.StatusNotFound, rr.Code)
				assert.Equal(t, "text/plain; charset=utf-8", rr.Result().Header.Get("Content-Type"), "the resource's own 404, not the 404 page")
				assertNoStore(t, rr)
			})
		}
	}
}

// The same "not found" answers, over a real connection: the header fields a client receives are the
// pair, with no Expires, on GET and on HEAD. The escaped prefix is sent as written, which the router
// matches by its decoded path.
func TestRegisterRoutes_APublicResourceNotFoundIsNoStoreOnTheWire(t *testing.T) {
	s := newRoutingTestServer(t, newRoutingDatabase(t))
	base := routingListener(t, s)

	for _, target := range []string{"/static/no-such-file.css", "/st%61tic/main.css", "/brand-assets/logo"} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			t.Run(method+" "+target, func(t *testing.T) {
				resp, _ := sendRouting(t, method, base+target)

				require.Equal(t, http.StatusNotFound, resp.StatusCode)
				assert.Equal(t, []string{"no-store"}, resp.Header.Values("Cache-Control"))
				assert.Equal(t, []string{"no-cache"}, resp.Header.Values("Pragma"))
				assert.Empty(t, resp.Header.Values("Expires"))
			})
		}
	}
}

// The resources themselves keep their lifetimes: the profile picture's own, beside the client logo's
// on GET, HEAD and its 304 (TestRegisterRoutes_TheListedRoutesCarryNoBrowserSession), the brand
// stylesheets' and assets' (TestRegisterRoutes_TheBrandStylesheetCarriesNoBrowserSession and
// TestRegisterRoutes_ABrandAssetCarriesNoBrowserSessionAndGrantsAFontToTheConsole), and the static
// files' (routes_static_cache_test.go). A static directory stays the 404 page
// (TestRegisterRoutes_NoRouteOutsideThePageBranchSendsACookie).
func TestRegisterRoutes_AProfilePictureKeepsItsOwnCachePolicy(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			database := newRoutingDatabase(t)
			database.On("GetUserBySubject", mock.Anything, mock.Anything, "pictured-user").
				Return(&record.User{ID: 6, Subject: "pictured-user"}, nil).Once()
			database.On("GetUserProfilePictureByUserID", mock.Anything, mock.Anything, int64(6)).
				Return(&record.UserProfilePicture{UserID: 6, Picture: []byte("a picture"), ContentType: "image/png"}, nil).Once()
			s := newRoutingTestServer(t, database)

			rr := serveRouting(s, method, "/userinfo/picture/pictured-user", nil)

			require.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, "no-store, no-cache, must-revalidate", rr.Result().Header.Get("Cache-Control"))
			assert.Equal(t, "image/png", rr.Result().Header.Get("Content-Type"))
		})
	}
}

// The public settings are no-store, whichever exit answers them: the handler's 200, the handler's
// own JSON 500, and the JSON 500 a step in front of the handler answers, a settings read that fails
// or a panic. The admin console, their reader, keeps its own copy for a time of its own (#825
// decision 3).
func TestRegisterRoutes_ThePublicSettingsAreNoStore(t *testing.T) {
	t.Run("the settings", func(t *testing.T) {
		s := newRoutingTestServer(t, newRoutingDatabase(t))

		rr := serveRouting(s, http.MethodGet, "/api/public/settings", nil)

		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		var body map[string]any
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
		assert.Equal(t, "Goiabada", body["appName"])
		assertNoStore(t, rr)
	})

	t.Run("the handler's own 500", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("PoolStats").Return(testPoolStats).Maybe()
		// The settings step reads the row, then the handler reads it again and fails.
		database.On("GetSettingsByID", mock.Anything, mock.Anything, int64(1)).
			Return(&record.Settings{ID: 1, AppName: "Goiabada"}, nil).Once()
		database.On("GetSettingsByID", mock.Anything, mock.Anything, int64(1)).
			Return(nil, errors.New("the settings row could not be read")).Once()
		s := newRoutingTestServer(t, database)

		rr := serveRouting(s, http.MethodGet, "/api/public/settings", nil)

		assertFaultFormat(t, "api", "", rr)
		assertNoStore(t, rr)
	})

	t.Run("a settings read that fails before the handler", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("PoolStats").Return(testPoolStats).Maybe()
		database.On("GetSettingsByID", mock.Anything, mock.Anything, int64(1)).
			Return(nil, errors.New("the settings row could not be read")).Once()
		s := newRoutingTestServer(t, database)

		rr := serveRouting(s, http.MethodGet, "/api/public/settings", nil)

		assertFaultFormat(t, "api", "", rr)
		assertNoStore(t, rr)
	})

	t.Run("a panic before the handler", func(t *testing.T) {
		s := newPanickingServer(t, "the settings read panicked")

		rr := serveRouting(s, http.MethodGet, "/api/public/settings", nil)

		assertFaultFormat(t, "api", "", rr)
		assertNoStore(t, rr)
	})

	// The router's 405 for another method is the root's answer, outside every branch, and is not
	// changed.
	t.Run("another method", func(t *testing.T) {
		s := newRoutingTestServer(t, newRoutingDatabase(t))

		rr := serveRouting(s, http.MethodPost, "/api/public/settings", nil)

		require.Equal(t, http.StatusMethodNotAllowed, rr.Code)
		sent := rr.Result().Header
		assert.Equal(t, "GET", sent.Get("Allow"))
		assert.Empty(t, sent.Values("Cache-Control"))
		assert.Empty(t, sent.Values("Pragma"))
	})
}
