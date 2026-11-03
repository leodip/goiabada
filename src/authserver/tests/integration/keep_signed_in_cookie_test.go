package integration

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The sign-in cookie follows the Keep users signed in after the browser closes setting, observed on
// the wire (#743 decisions 2 and 5): under Always a signed-in browser session's cookie carries a
// Max-Age, under Never it carries neither Max-Age nor Expires, and under Let each user choose a
// session with no recorded answer counts as unticked and gets none. A sign-in in progress keeps its
// 30 minutes and the device cookie its lifetime in every mode. Until the password page asks, no
// session records an answer, so a ticked box is the store's and the rule's unit tests' to pin.

// keepSignedInModes are the three modes, by their wire values.
var keepSignedInModes = []record.KeepSignedIn{record.KeepSignedInAlways, record.KeepSignedInAsk, record.KeepSignedInNever}

// setKeepSignedIn makes mode the deployment's setting for the rest of the test, and puts the row back
// when the test ends.
func setKeepSignedIn(t *testing.T, mode record.KeepSignedIn) {
	t.Helper()
	changeSettings(t, func(settings *record.Settings) { settings.KeepSignedIn = mode })
}

// endsWithTheBrowser reports whether a Set-Cookie carried neither Max-Age nor Expires: net/http
// parses an absent Max-Age to 0 and one of 0 to -1, and leaves RawExpires empty with no Expires.
func endsWithTheBrowser(cookie *http.Cookie) bool {
	return cookie.MaxAge == 0 && cookie.RawExpires == "" && cookie.Expires.IsZero()
}

// splitAtCompleted divides the session cookies a sign-in set into those written while it was in
// progress and those written once /auth/completed bound it to a session.
func splitAtCompleted(t *testing.T, sessions []observedDeviceCookie) (inProgress, signedIn []observedDeviceCookie) {
	t.Helper()
	for _, set := range sessions {
		if set.path == "/auth/completed" || len(signedIn) > 0 {
			signedIn = append(signedIn, set)
		} else {
			inProgress = append(inProgress, set)
		}
	}
	require.NotEmpty(t, inProgress, "the sign-in in progress writes its cookie")
	require.NotEmpty(t, signedIn, "/auth/completed binds the session and writes the sign-in cookie")
	return inProgress, signedIn
}

// Each mode, one fresh sign-in: the cookies of the sign-in in progress carry its 30 minutes, the
// device cookie the max lifetime, and the signed-in cookie written on /auth/completed and after an
// expiry under Always alone.
func TestKeepSignedIn_TheSignInCookieFollowsTheSettingAndNothingElseDoes(t *testing.T) {
	for _, mode := range keepSignedInModes {
		t.Run(string(mode), func(t *testing.T) {
			setKeepSignedIn(t, mode)
			f := newDeviceFixture(t)
			browser := newDeviceBrowser(t)
			browser.sessions = nil

			f.signIn(t, browser)

			inProgress, signedIn := splitAtCompleted(t, browser.sessions)
			for _, set := range inProgress {
				assert.InDelta(t, 1800, set.cookie.MaxAge, 3, "the sign-in in progress keeps its 30 minutes, on %v", set.path)
			}
			assert.Equal(t, 86400, theDeviceCookieSet(t, browser).cookie.MaxAge, "the device cookie keeps the max lifetime")

			for _, set := range signedIn {
				if mode == record.KeepSignedInAlways {
					assert.InDelta(t, 7200, set.cookie.MaxAge, 3,
						"the sign-in cookie outlives the browser, for the idle timeout, on %v", set.path)
				} else {
					assert.True(t, endsWithTheBrowser(set.cookie),
						"the sign-in cookie ends with the browser, on %v: Max-Age %d, Expires %q",
						set.path, set.cookie.MaxAge, set.cookie.RawExpires)
				}
			}
		})
	}
}

// signOnAgain sends browser through the client's authorization request once more, following the
// auth server's own redirects, as a single sign-on that reuses the browser's session: no password,
// and back at the client with a code.
func (f *deviceFixture) signOnAgain(t *testing.T, browser *deviceBrowser) {
	t.Helper()
	authServer, err := url.Parse(appConfig.AuthServer.BaseURL)
	require.NoError(t, err)

	target := f.authorizeURL()
	for range 10 {
		resp, err := browser.Get(target)
		require.NoError(t, err)
		_ = resp.Body.Close()
		require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, resp.StatusCode,
			"the single sign-on redirects, never stopping at a page, from %v", target)
		location, err := resp.Location()
		require.NoError(t, err)
		if location.Host != authServer.Host {
			assert.True(t, strings.HasPrefix(location.String(), f.redirectURI.URI), "back at the client")
			assert.NotEmpty(t, location.Query().Get("code"), "with a code")
			return
		}
		target = location.String()
	}
	t.Fatal("the single sign-on never reached the client")
}

// A browser session signed in under Always holds a cookie that outlives the browser. Once the
// deployment switches, its next cookie write follows the new mode: a single sign-on that reuses the
// session under Never, or under Let each user choose, where the session recorded no answer and so
// counts as unticked, writes a cookie that ends with the browser (#743 decision 5).
func TestKeepSignedIn_ASessionsNextCookieWriteFollowsASwitchedSetting(t *testing.T) {
	for _, mode := range []record.KeepSignedIn{record.KeepSignedInNever, record.KeepSignedInAsk} {
		t.Run(string(mode), func(t *testing.T) {
			setKeepSignedIn(t, record.KeepSignedInAlways)
			f := newDeviceFixture(t)
			browser := newDeviceBrowser(t)
			f.signIn(t, browser)
			_, signedIn := splitAtCompleted(t, browser.sessions)
			require.Positive(t, signedIn[len(signedIn)-1].cookie.MaxAge, "signed in under Always, the cookie persists")

			setKeepSignedIn(t, mode)
			browser.sessions = nil
			f.signOnAgain(t, browser)

			require.NotEmpty(t, browser.sessions, "the single sign-on writes the session cookie")
			for _, set := range browser.sessions {
				assert.True(t, endsWithTheBrowser(set.cookie),
					"the cookie ends with the browser from the next write, on %v: Max-Age %d", set.path, set.cookie.MaxAge)
			}
			assert.Len(t, f.storedSessions(t), 1, "the session is the same one, reused")
		})
	}
}

// A page request past the touch threshold refreshes a signed-in session in every mode, and sends its
// cookie again only under Always: one that ends with the browser has no expiry to keep up (#743
// decision 8).
func TestKeepSignedIn_APageRefreshSendsTheCookieAgainOnlyWhenItOutlivesTheBrowser(t *testing.T) {
	for _, mode := range keepSignedInModes {
		t.Run(string(mode), func(t *testing.T) {
			setKeepSignedIn(t, mode)
			cookie, hash, _ := staleSignedInBrowserSession(t)
			staleRow := readBrowserSessionRow(t, hash)

			resp := getWithSessionCookie(t, appConfig.AuthServer.BaseURL+"/auth/logout/declined", cookie)
			require.Equal(t, http.StatusOK, resp.StatusCode)

			row := readBrowserSessionRow(t, hash)
			assert.True(t, row.LastAccessed.After(staleRow.LastAccessed), "the row was touched")
			var reissued []*http.Cookie
			for _, set := range resp.Cookies() {
				if set.Name == browserSessionCookieName() {
					reissued = append(reissued, set)
				}
			}
			if mode == record.KeepSignedInAlways {
				require.Len(t, reissued, 1, "the cookie is sent again")
				assert.InDelta(t, time.Until(row.ExpiresAt).Seconds(), reissued[0].MaxAge, 3, "and expires with the row")
			} else {
				assert.Empty(t, reissued, "no cookie is sent")
			}
		})
	}
}
