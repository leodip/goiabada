package integration

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The password page's Keep me signed in box, observed on the wire (#743 decisions 2 and 4): under
// Let each user choose the page shows it unticked, and the answer decides whether the sign-in cookie
// /auth/completed writes, and every write after it, outlives the browser. A single sign-on that
// reuses the session keeps the answer; a password entered again (prompt=login) replaces it, and one
// entered with no box, under Always or Never, leaves the session with no answer, which counts as
// unticked.

// keepSignedInBox is the box on a rendered password page: whether it is there, and whether it is
// ticked.
type keepSignedInBox struct {
	shown, ticked bool
}

// readKeepSignedInBox reads the box off the password page inside its form, and puts the body back for
// the next reader.
func readKeepSignedInBox(t *testing.T, pwdPage *http.Response) keepSignedInBox {
	t.Helper()
	body, err := io.ReadAll(pwdPage.Body)
	require.NoError(t, err)
	pwdPage.Body = io.NopCloser(strings.NewReader(string(body)))
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
	require.NoError(t, err)

	input := doc.Find(`form input[name="keepSignedIn"]`)
	if input.Length() == 0 {
		return keepSignedInBox{}
	}
	require.Equal(t, 1, input.Length(), "one box")
	inputType, _ := input.Attr("type")
	assert.Equal(t, "checkbox", inputType)
	_, ticked := input.Attr("checked")
	return keepSignedInBox{shown: true, ticked: ticked}
}

// signInAnswering signs the fixture's user in on browser through authorizeURL with the password,
// ticking the box when tick says so, and answers the box the password page showed. The browser's
// session cookies are noted from the authorization request on.
func (f *deviceFixture) signInAnswering(t *testing.T, browser *deviceBrowser, authorizeURL string,
	tick bool) keepSignedInBox {

	t.Helper()
	browser.sessions = nil
	// follow loads target and answers where it redirects to, which must be the path next.
	follow := func(target, next string) string {
		resp := loadPage(t, browser.Client, target)
		defer func() { _ = resp.Body.Close() }()
		return assertRedirect(t, resp, next)
	}
	loc := follow(follow(authorizeURL, "/auth/level1"), "/auth/pwd")
	pwdPage := loadPage(t, browser.Client, loc)
	defer func() { _ = pwdPage.Body.Close() }()
	require.Equal(t, http.StatusOK, pwdPage.StatusCode)
	box := readKeepSignedInBox(t, pwdPage)

	form := url.Values{
		"email":      {f.user.Email},
		"password":   {f.password},
		"ceremonyId": {getCeremonyIdFromPage(t, pwdPage)},
	}
	if tick {
		require.True(t, box.shown, "a box to tick")
		form.Set("keepSignedIn", "true")
	}
	request, err := http.NewRequest(http.MethodPost, loc, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Referer", loc)
	request.Header.Set("Origin", appConfig.AuthServer.BaseURL)
	submitted, err := browser.Do(request)
	require.NoError(t, err)
	_ = submitted.Body.Close()

	loc = follow(follow(assertRedirect(t, submitted, "/auth/level1completed"), "/auth/completed"), "/auth/issue")
	issued := loadPage(t, browser.Client, loc)
	defer func() { _ = issued.Body.Close() }()
	code, _ := getCodeAndStateFromUrl(t, issued)
	require.NotEmpty(t, code, "the sign-in reaches the client with a code")
	return box
}

// promptLogin is the fixture's authorization request asking for a fresh sign-in.
func (f *deviceFixture) promptLogin() string {
	return f.authorizeURL() + "&prompt=login"
}

// assertSignedInCookies holds every sign-in cookie /auth/completed and the steps after it wrote to
// outliving the browser, for the seeded idle timeout, or to ending with it.
func assertSignedInCookies(t *testing.T, signedIn []observedDeviceCookie, outlivesTheBrowser bool) {
	t.Helper()
	for _, set := range signedIn {
		if outlivesTheBrowser {
			assert.InDelta(t, 7200, set.cookie.MaxAge, 3, "the sign-in cookie outlives the browser, on %v", set.path)
		} else {
			assert.True(t, endsWithTheBrowser(set.cookie),
				"the sign-in cookie ends with the browser, on %v: Max-Age %d, Expires %q",
				set.path, set.cookie.MaxAge, set.cookie.RawExpires)
		}
	}
}

// The page shows the box under Let each user choose alone, and unticked.
func TestKeepMeSignedIn_ThePasswordPageAsksUnderLetEachUserChooseAlone(t *testing.T) {
	for _, mode := range keepSignedInModes {
		t.Run(string(mode), func(t *testing.T) {
			setKeepSignedIn(t, mode)
			f := newDeviceFixture(t)

			box := f.signInAnswering(t, newDeviceBrowser(t), f.authorizeURL(), false)

			assert.Equal(t, mode == record.KeepSignedInAsk, box.shown)
			assert.False(t, box.ticked, "a pre-ticked box is not consent")
		})
	}
}

// Ticked, the sign-in cookie lasts as long as the session; unticked, it ends with the browser. The
// sign-in in progress keeps its 30 minutes and the device cookie its lifetime either way.
func TestKeepMeSignedIn_TheAnswerDecidesTheSignInCookie(t *testing.T) {
	for _, tick := range []bool{true, false} {
		t.Run(map[bool]string{true: "ticked", false: "unticked"}[tick], func(t *testing.T) {
			setKeepSignedIn(t, record.KeepSignedInAsk)
			f := newDeviceFixture(t)
			browser := newDeviceBrowser(t)
			browser.observed = nil

			f.signInAnswering(t, browser, f.authorizeURL(), tick)

			inProgress, signedIn := splitAtCompleted(t, browser.sessions)
			assert.Equal(t, "/auth/completed", signedIn[0].path, "the sign-in cookie is written where the session is bound")
			assertSignedInCookies(t, signedIn, tick)
			for _, set := range inProgress {
				assert.InDelta(t, 1800, set.cookie.MaxAge, 3, "the sign-in in progress keeps its 30 minutes, on %v", set.path)
			}
			assert.Equal(t, 86400, theDeviceCookieSet(t, browser).cookie.MaxAge, "the device cookie keeps the max lifetime")
		})
	}
}

// A single sign-on that reuses the session enters no password, and keeps the answer.
func TestKeepMeSignedIn_ASingleSignOnKeepsTheAnswer(t *testing.T) {
	for _, tick := range []bool{true, false} {
		t.Run(map[bool]string{true: "ticked", false: "unticked"}[tick], func(t *testing.T) {
			setKeepSignedIn(t, record.KeepSignedInAsk)
			f := newDeviceFixture(t)
			browser := newDeviceBrowser(t)
			f.signInAnswering(t, browser, f.authorizeURL(), tick)

			browser.sessions = nil
			f.signOnAgain(t, browser)

			require.NotEmpty(t, browser.sessions, "the single sign-on writes the session cookie")
			assertSignedInCookies(t, browser.sessions, tick)
			assert.Len(t, f.storedSessions(t), 1, "the session is the same one, reused")
		})
	}
}

// A password entered again over the session (prompt=login) asks again, and the new answer replaces
// the old one from /auth/completed on.
func TestKeepMeSignedIn_PromptLoginReplacesTheAnswer(t *testing.T) {
	for _, tc := range []struct {
		name          string
		first, second bool
	}{
		{"ticked, then unticked", true, false},
		{"unticked, then ticked", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setKeepSignedIn(t, record.KeepSignedInAsk)
			f := newDeviceFixture(t)
			browser := newDeviceBrowser(t)
			f.signInAnswering(t, browser, f.authorizeURL(), tc.first)

			box := f.signInAnswering(t, browser, f.promptLogin(), tc.second)

			assert.Equal(t, keepSignedInBox{shown: true}, box, "asked again, unticked")
			_, signedIn := splitAtCompleted(t, browser.sessions)
			assertSignedInCookies(t, signedIn, tc.second)
			assert.Len(t, f.storedSessions(t), 1, "the session is the same one, reused")

			browser.sessions = nil
			f.signOnAgain(t, browser)
			assertSignedInCookies(t, browser.sessions, tc.second)
		})
	}
}

// A password entered under Always or Never shows no box and leaves the session with no answer: back
// under Let each user choose, the session counts as unticked, whatever an earlier sign-in ticked.
func TestKeepMeSignedIn_APasswordEnteredWithNoBoxLeavesNoAnswer(t *testing.T) {
	for _, mode := range []record.KeepSignedIn{record.KeepSignedInAlways, record.KeepSignedInNever} {
		t.Run(string(mode), func(t *testing.T) {
			setKeepSignedIn(t, record.KeepSignedInAsk)
			f := newDeviceFixture(t)
			browser := newDeviceBrowser(t)
			f.signInAnswering(t, browser, f.authorizeURL(), true)

			setKeepSignedIn(t, mode)
			box := f.signInAnswering(t, browser, f.promptLogin(), false)
			require.False(t, box.shown, "no box")

			setKeepSignedIn(t, record.KeepSignedInAsk)
			browser.sessions = nil
			f.signOnAgain(t, browser)

			require.NotEmpty(t, browser.sessions, "the single sign-on writes the session cookie")
			assertSignedInCookies(t, browser.sessions, false)
		})
	}
}
