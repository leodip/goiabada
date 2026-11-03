package integration

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The refresh of a signed-in browser session, observed on the wire (#743 decisions 8 and 9): a page
// request that finds the session's row more than ten seconds stale moves the row's idle deadline and
// sends the session cookie again with the row's new expiry, so a browser that only reads keeps its
// cookie as long as the row lives; every other request reads the session without moving the row,
// so no reissued cookie rides on an answer a shared cache may store.

// staleSignedInBrowserSession signs a user in and returns the browser's session cookie and its row's
// hash, with the row made a minute stale and five minutes from expiring: past the touch threshold,
// and with an expiry no touch would choose, so a touch shows in the row.
func staleSignedInBrowserSession(t *testing.T) (*http.Cookie, string, *record.Client) {
	t.Helper()

	httpClient, client, _, _ := createSessionWithAcrLevel1(t)
	cookie := requireSessionCookie(t, httpClient)
	hash := hashutil.HashString(decodeSessionIdentifier(t, cookie))

	now := time.Now().UTC()
	touched, err := database.TouchBrowserSession(context.Background(), nil, sessionkeys.AuthServerSessionName, hash,
		now.Add(-time.Minute), now.Add(5*time.Minute))
	require.NoError(t, err)
	require.True(t, touched, "the signed-in session has a row")
	return cookie, hash, client
}

// readBrowserSessionRow reads the row the hash names, which must be live.
func readBrowserSessionRow(t *testing.T, hash string) *record.BrowserSession {
	t.Helper()
	row, err := database.GetBrowserSessionByOwnerAndSessionIdHash(context.Background(), nil,
		sessionkeys.AuthServerSessionName, hash, time.Now().UTC())
	require.NoError(t, err)
	require.NotNil(t, row, "the browser session is live")
	return row
}

// getWithSessionCookie sends a GET carrying only the session cookie, from a browser with nothing
// else, and returns the response, whose Set-Cookie fields are then the ones this request caused.
func getWithSessionCookie(t *testing.T, target string, cookie *http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestSessionRefresh_APageRequestPastTheThresholdSendsTheCookieWithTheRowsNewExpiry(t *testing.T) {
	cookie, hash, _ := staleSignedInBrowserSession(t)
	staleRow := readBrowserSessionRow(t, hash)

	resp := getWithSessionCookie(t, appConfig.AuthServer.BaseURL+"/auth/logout/declined", cookie)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var reissued []*http.Cookie
	for _, set := range resp.Cookies() {
		if set.Name == browserSessionCookieName() {
			reissued = append(reissued, set)
		}
	}
	require.Len(t, reissued, 1, "the page answer sends the session cookie again")
	assert.Equal(t, decodeSessionIdentifier(t, cookie), decodeSessionIdentifier(t, reissued[0]),
		"naming the same session")
	assert.InDelta(t, 7200, reissued[0].MaxAge, 3,
		"for the idle timeout from now, two hours on a seeded deployment")
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"), "on an answer no cache may store")

	row := readBrowserSessionRow(t, hash)
	assert.True(t, row.LastAccessed.After(staleRow.LastAccessed), "the row was touched")
	assert.InDelta(t, time.Until(row.ExpiresAt).Seconds(), reissued[0].MaxAge, 3,
		"and the cookie expires with the row")
}

// A client logo is answered cacheable, and the consent page loads one with the user's cookie: its
// answer carries no Set-Cookie and the row does not move, however stale. Discovery, on the protocol
// branch, the same.
func TestSessionRefresh_ACacheableAnswerSendsNoCookieAndLeavesTheRowAlone(t *testing.T) {
	cookie, hash, client := staleSignedInBrowserSession(t)
	require.NoError(t, database.CreateClientLogo(context.Background(), nil, &record.ClientLogo{
		ClientId: client.Id, Logo: createTestPNGImage(16, 16), ContentType: "image/png",
	}))
	staleRow := readBrowserSessionRow(t, hash)

	for name, test := range map[string]struct {
		path         string
		cacheControl string
	}{
		"a client logo": {path: "/client/logo/" + client.ClientIdentifier, cacheControl: "public, max-age=300, must-revalidate"},
		"discovery":     {path: "/.well-known/openid-configuration"},
	} {
		t.Run(name, func(t *testing.T) {
			resp := getWithSessionCookie(t, appConfig.AuthServer.BaseURL+test.path, cookie)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			if test.cacheControl != "" {
				assert.Equal(t, test.cacheControl, resp.Header.Get("Cache-Control"), "the answer is cacheable")
			}
			assert.Empty(t, resp.Header.Values("Set-Cookie"), "and carries no cookie")

			row := readBrowserSessionRow(t, hash)
			assert.Equal(t, staleRow.LastAccessed, row.LastAccessed, "the row was not touched")
			assert.Equal(t, staleRow.ExpiresAt, row.ExpiresAt, "and its expiry did not move")
		})
	}
}
