package usersession

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// The device cookie (#564 decision 4)
//
// A sign-in that starts a new session gives the browser a random identifier in a cookie of its own,
// or gives it back the one it already holds, and records the identifier's SHA-256 on the session.
// The same-device sweep keys on that digest, so two browsers sending one user agent from one
// address are two devices.
// =============================================================================

// thisDevice is the device cookie the tests' browser holds, and thisDeviceId its SHA-256 as a
// session stores it, computed with sha256sum rather than by the code under test.
const (
	thisDevice   = "5f0c8e2a9d4b7163e8a1c0f9b2d3e4a5968778695a4b3c2d1e0f1a2b3c4d5e6f"
	thisDeviceId = "6627ab4c37892875ecb04a9929aab4e58ce8124cd5e5b95d2fca66740b772816"
)

// otherDeviceId is the digest of another browser's identifier,
// 0e9d8c7b6a5f4e3d2c1b0a99887766554433221100ffeeddccbbaa9988776655.
const otherDeviceId = "58e65ad61e99665aaed2d4d802cf87adac1c4e37e4433c2436a49a04ae9ff1e1"

// fourHundredDaysInSeconds is the cookie's Max-Age, the most RFC 6265bis lets a browser keep one.
const fourHundredDaysInSeconds = 400 * 24 * 60 * 60

var lowerHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// onDevice is req carrying value under the cookie name a plain-http deployment uses.
func onDevice(req *http.Request, value string) *http.Request {
	req.AddCookie(&http.Cookie{Name: "authserver_device", Value: value})
	return req
}

// deviceCookieOf is the one device cookie rr's response sets, under either name, or fails.
func deviceCookieOf(t *testing.T, rr *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	var found []*http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == "authserver_device" || c.Name == "__Host-authserver_device" {
			found = append(found, c)
		}
	}
	require.Len(t, found, 1, "a sign-in that starts a session sets the device cookie once")
	return found[0]
}

func noDeviceCookieIn(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	for _, c := range rr.Result().Cookies() {
		assert.NotContains(t, []string{"authserver_device", "__Host-authserver_device"}, c.Name,
			"no device cookie is written")
	}
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func startOnce(t *testing.T, m *startSessionMocks, req *http.Request) (*httptest.ResponseRecorder, *record.UserSession) {
	t.Helper()
	captured := m.expectPersistThroughCommit(123, nil)
	rr := httptest.NewRecorder()
	_, _, err := m.manager.StartNewUserSession(rr, req, 7,
		authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 0, nil, "192.168.1.50", nil)
	require.NoError(t, err)
	return rr, *captured
}

// A browser with no device cookie gets one, with the session cookie's attributes on plain http and
// 400 days to live, holding 32 random bytes; the session records the value's SHA-256, never the
// value itself.
func TestStartNewUserSession_ABrowserWithNoDeviceCookieGetsOne(t *testing.T) {
	m := newStartSessionMocks(t)
	req := newSessionRequest("192.168.1.50:54321", chromeUserAgent)
	req.Header.Del("Cookie")

	rr, session := startOnce(t, m, req)

	cookie := deviceCookieOf(t, rr)
	assert.Equal(t, "authserver_device", cookie.Name, "the bare name on plain http")
	assert.Regexp(t, lowerHex64, cookie.Value, "32 bytes, hex encoded")
	assert.Equal(t, "/", cookie.Path)
	assert.Empty(t, cookie.Domain, "a host-only cookie")
	assert.True(t, cookie.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
	assert.False(t, cookie.Secure, "not Secure on plain http")
	assert.Equal(t, fourHundredDaysInSeconds, cookie.MaxAge)

	assert.Equal(t, sha256Hex(cookie.Value), session.DeviceId, "the session stores the value's digest")
	assert.NotEqual(t, cookie.Value, session.DeviceId)
}

// Two browsers with no cookie are two devices: each value is drawn afresh.
func TestStartNewUserSession_EachNewDeviceGetsItsOwnIdentifier(t *testing.T) {
	first, _ := startOnce(t, newStartSessionMocks(t), withoutCookies(newSessionRequest("192.168.1.50:54321", chromeUserAgent)))
	second, _ := startOnce(t, newStartSessionMocks(t), withoutCookies(newSessionRequest("192.168.1.50:54321", chromeUserAgent)))

	assert.NotEqual(t, deviceCookieOf(t, first).Value, deviceCookieOf(t, second).Value)
}

// On https the cookie carries the __Host- prefix and Secure, as the session cookie does, so a
// sibling subdomain cannot plant one.
func TestStartNewUserSession_OnHTTPSTheDeviceCookieIsAHostCookie(t *testing.T) {
	m := newStartSessionMocks(t)
	m.manager.secureCookies = true

	rr, session := startOnce(t, m, withoutCookies(newSessionRequest("192.168.1.50:54321", chromeUserAgent)))

	cookie := deviceCookieOf(t, rr)
	assert.Equal(t, "__Host-authserver_device", cookie.Name)
	assert.True(t, cookie.Secure)
	assert.Equal(t, "/", cookie.Path)
	assert.Empty(t, cookie.Domain)
	assert.True(t, cookie.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
	assert.Equal(t, fourHundredDaysInSeconds, cookie.MaxAge)
	assert.Equal(t, sha256Hex(cookie.Value), session.DeviceId)
}

// A browser that holds an identifier keeps it: the same value comes back with a fresh Max-Age, and
// the session records its digest.
func TestStartNewUserSession_ABrowserWithADeviceCookieKeepsIt(t *testing.T) {
	m := newStartSessionMocks(t)

	rr, session := startOnce(t, m, onDevice(withoutCookies(newSessionRequest("192.168.1.50:54321", chromeUserAgent)), thisDevice))

	cookie := deviceCookieOf(t, rr)
	assert.Equal(t, thisDevice, cookie.Value)
	assert.Equal(t, fourHundredDaysInSeconds, cookie.MaxAge, "the lifetime starts again")
	assert.Equal(t, thisDeviceId, session.DeviceId)
}

// On https the identifier is read from the prefixed cookie, and a bare-named one, which anyone able
// to set a cookie for a sibling host could have planted, is not read: the browser gets a new value.
func TestStartNewUserSession_OnHTTPSOnlyThePrefixedCookieIsRead(t *testing.T) {
	t.Run("the prefixed cookie is read", func(t *testing.T) {
		m := newStartSessionMocks(t)
		m.manager.secureCookies = true
		req := withoutCookies(newSessionRequest("192.168.1.50:54321", chromeUserAgent))
		req.AddCookie(&http.Cookie{Name: "__Host-authserver_device", Value: thisDevice})

		rr, session := startOnce(t, m, req)

		assert.Equal(t, thisDevice, deviceCookieOf(t, rr).Value)
		assert.Equal(t, thisDeviceId, session.DeviceId)
	})

	t.Run("a bare-named cookie is not", func(t *testing.T) {
		m := newStartSessionMocks(t)
		m.manager.secureCookies = true

		rr, session := startOnce(t, m, onDevice(withoutCookies(newSessionRequest("192.168.1.50:54321", chromeUserAgent)), thisDevice))

		cookie := deviceCookieOf(t, rr)
		assert.NotEqual(t, thisDevice, cookie.Value)
		assert.Regexp(t, lowerHex64, cookie.Value)
		assert.Equal(t, sha256Hex(cookie.Value), session.DeviceId)
		assert.NotEqual(t, thisDeviceId, session.DeviceId)
	})
}

// A value that is not one this server minted, 32 bytes as 64 lower-case hex digits, is replaced
// by a new one rather than stored: whatever a browser sends is not an identifier it can choose.
func TestStartNewUserSession_AnUnparseableDeviceCookieIsReplaced(t *testing.T) {
	for name, value := range map[string]string{
		"empty":              "",
		"too short":          thisDevice[:62],
		"too long":           thisDevice + "00",
		"not hex":            "zz" + thisDevice[2:],
		"upper-case hex":     "5F0C8E2A9D4B7163E8A1C0F9B2D3E4A5968778695A4B3C2D1E0F1A2B3C4D5E6F",
		"base64 of 32 bytes": "XwyOKp1LcWPoocD5stPkpZaHeGlaSzwtHg8aKzxNXm8",
	} {
		t.Run(name, func(t *testing.T) {
			m := newStartSessionMocks(t)

			rr, session := startOnce(t, m, onDevice(withoutCookies(newSessionRequest("192.168.1.50:54321", chromeUserAgent)), value))

			cookie := deviceCookieOf(t, rr)
			assert.NotEqual(t, value, cookie.Value)
			assert.Regexp(t, lowerHex64, cookie.Value)
			assert.Equal(t, sha256Hex(cookie.Value), session.DeviceId)
		})
	}
}

// The cookie is written only by a sign-in that started a session: a refused one, or one whose
// transaction failed, leaves the browser's cookie as it was.
func TestStartNewUserSession_AFailedStartWritesNoDeviceCookie(t *testing.T) {
	t.Run("refused before anything is read", func(t *testing.T) {
		m := newStartSessionMocks(t)
		rr := httptest.NewRecorder()

		_, _, err := m.manager.StartNewUserSession(rr, newSessionRequest("192.168.1.50:54321", chromeUserAgent), 7,
			authenticationOf(123, "pwd", record.AcrLevel1, nil), 0, nil, "192.168.1.50", nil)

		require.Error(t, err)
		noDeviceCookieIn(t, rr)
	})

	t.Run("the transaction fails", func(t *testing.T) {
		m := newStartSessionMocks(t)
		dbErr := errors.New("database is down")
		datamocks.ExpectRunInTransaction(m.db, txSentinel)
		m.db.On("CreateUserSession", mock.Anything, txSentinel, mock.Anything).Return(dbErr).Once()
		rr := httptest.NewRecorder()

		_, _, err := m.manager.StartNewUserSession(rr, newSessionRequest("192.168.1.50:54321", chromeUserAgent), 7,
			authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 0, nil, "192.168.1.50", nil)

		require.ErrorIs(t, err, dbErr)
		noDeviceCookieIn(t, rr)
	})
}

// withoutCookies drops every cookie req carries, for a case about which device cookie it holds.
func withoutCookies(req *http.Request) *http.Request {
	req.Header.Del("Cookie")
	return req
}
