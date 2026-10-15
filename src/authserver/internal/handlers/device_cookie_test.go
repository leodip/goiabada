package handlers

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/useragent"
	"github.com/leodip/goiabada/authserver/internal/usersession"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// The device cookie (#564 decision 4)
//
// A sign-in that starts a new session gives the browser a random identifier in a cookie of its own,
// or gives it back the one it already holds, and the session records the identifier's SHA-256 (the
// session start's own tests). The same-device sweep keys on that digest, so two browsers sending one
// user agent from one address are two devices.
// =============================================================================

// thisDevice is a device identifier as this server mints one: 32 bytes as lower-case hex.
const thisDevice = "5f0c8e2a9d4b7163e8a1c0f9b2d3e4a5968778695a4b3c2d1e0f1a2b3c4d5e6f"

// chromeUserAgent is a desktop UA string, so the display labels are populated rather than empty.
const chromeUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// fourHundredDaysInSeconds is the cookie's Max-Age, the most RFC 6265bis lets a browser keep one.
const fourHundredDaysInSeconds = 400 * 24 * 60 * 60

var lowerHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

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

// noDeviceCookieIn fails when rr's response sets a device cookie under either name.
func noDeviceCookieIn(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	for _, c := range rr.Result().Cookies() {
		assert.NotContains(t, []string{"authserver_device", "__Host-authserver_device"}, c.Name,
			"no device cookie is written")
	}
}

// browserRequest is a sign-in request sending chromeUserAgent and, when the name is not empty, a
// device cookie of that name and value.
func browserRequest(cookieName, cookieValue string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/auth/completed", nil)
	req.Header.Set("User-Agent", chromeUserAgent)
	if cookieName != "" {
		req.AddCookie(&http.Cookie{Name: cookieName, Value: cookieValue})
	}
	return req
}

// readAndWrite is what /auth/completed's create arm does with the cookie once the new session is
// bound: the device read from the request, and its identifier written back.
func readAndWrite(t *testing.T, deviceCookie *DeviceCookie, req *http.Request) (usersession.Device, *http.Cookie) {
	t.Helper()
	device := deviceCookie.read(req)
	rr := httptest.NewRecorder()
	deviceCookie.write(rr, device.Identifier)
	return device, deviceCookieOf(t, rr)
}

// A browser with no device cookie gets one, with the session cookie's attributes on plain http and
// 400 days to live, holding 32 random bytes, and the device is new.
func TestDeviceCookie_ABrowserWithNoDeviceCookieGetsOne(t *testing.T) {
	device, cookie := readAndWrite(t, NewDeviceCookie(false), browserRequest("", ""))

	assert.True(t, device.New, "an identifier minted for this sign-in")
	assert.Equal(t, "authserver_device", cookie.Name, "the bare name on plain http")
	assert.Regexp(t, lowerHex64, cookie.Value, "32 bytes, hex encoded")
	assert.Equal(t, device.Identifier, cookie.Value)
	assert.Equal(t, "/", cookie.Path)
	assert.Empty(t, cookie.Domain, "a host-only cookie")
	assert.True(t, cookie.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
	assert.False(t, cookie.Secure, "not Secure on plain http")
	assert.Equal(t, fourHundredDaysInSeconds, cookie.MaxAge)
}

// Two browsers with no cookie are two devices: each value is drawn afresh.
func TestDeviceCookie_EachNewDeviceGetsItsOwnIdentifier(t *testing.T) {
	first, _ := readAndWrite(t, NewDeviceCookie(false), browserRequest("", ""))
	second, _ := readAndWrite(t, NewDeviceCookie(false), browserRequest("", ""))

	assert.NotEqual(t, first.Identifier, second.Identifier)
}

// On https the cookie carries the __Host- prefix and Secure, as the session cookie does, so a
// sibling subdomain cannot plant one.
func TestDeviceCookie_OnHTTPSTheDeviceCookieIsAHostCookie(t *testing.T) {
	device, cookie := readAndWrite(t, NewDeviceCookie(true), browserRequest("", ""))

	assert.Equal(t, "__Host-authserver_device", cookie.Name)
	assert.True(t, cookie.Secure)
	assert.Equal(t, "/", cookie.Path)
	assert.Empty(t, cookie.Domain)
	assert.True(t, cookie.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
	assert.Equal(t, fourHundredDaysInSeconds, cookie.MaxAge)
	assert.Equal(t, device.Identifier, cookie.Value)
}

// A browser that holds an identifier keeps it: the same value comes back with a fresh Max-Age, and
// the device is not new.
func TestDeviceCookie_ABrowserWithADeviceCookieKeepsIt(t *testing.T) {
	device, cookie := readAndWrite(t, NewDeviceCookie(false), browserRequest("authserver_device", thisDevice))

	assert.False(t, device.New)
	assert.Equal(t, thisDevice, device.Identifier)
	assert.Equal(t, thisDevice, cookie.Value)
	assert.Equal(t, fourHundredDaysInSeconds, cookie.MaxAge, "the lifetime starts again")
}

// On https the identifier is read from the prefixed cookie, and a bare-named one, which anyone able
// to set a cookie for a sibling host could have planted, is not read: the browser gets a new value.
func TestDeviceCookie_OnHTTPSOnlyThePrefixedCookieIsRead(t *testing.T) {
	t.Run("the prefixed cookie is read", func(t *testing.T) {
		device, cookie := readAndWrite(t, NewDeviceCookie(true), browserRequest("__Host-authserver_device", thisDevice))

		assert.False(t, device.New)
		assert.Equal(t, thisDevice, device.Identifier)
		assert.Equal(t, thisDevice, cookie.Value)
	})

	t.Run("a bare-named cookie is not", func(t *testing.T) {
		device, cookie := readAndWrite(t, NewDeviceCookie(true), browserRequest("authserver_device", thisDevice))

		assert.True(t, device.New)
		assert.NotEqual(t, thisDevice, device.Identifier)
		assert.Regexp(t, lowerHex64, cookie.Value)
		assert.Equal(t, device.Identifier, cookie.Value)
	})
}

// A value that is not one this server minted, 32 bytes as 64 lower-case hex digits, is replaced
// by a new one rather than read: whatever a browser sends is not an identifier it can choose.
func TestDeviceCookie_AnUnparseableDeviceCookieIsReplaced(t *testing.T) {
	for name, value := range map[string]string{
		"empty":              "",
		"too short":          thisDevice[:62],
		"too long":           thisDevice + "00",
		"not hex":            "zz" + thisDevice[2:],
		"upper-case hex":     "5F0C8E2A9D4B7163E8A1C0F9B2D3E4A5968778695A4B3C2D1E0F1A2B3C4D5E6F",
		"base64 of 32 bytes": "XwyOKp1LcWPoocD5stPkpZaHeGlaSzwtHg8aKzxNXm8",
	} {
		t.Run(name, func(t *testing.T) {
			device, cookie := readAndWrite(t, NewDeviceCookie(false), browserRequest("authserver_device", value))

			assert.True(t, device.New)
			assert.NotEqual(t, value, cookie.Value)
			assert.Regexp(t, lowerHex64, cookie.Value)
		})
	}
}

// The display labels are whatever useragent.Labels derives from the request, whose exhaustive table
// lives at its own seam, and the raw header is the string the browser sent, not a parse of it.
func TestDeviceCookie_TheLabelsAndTheHeaderAreTheRequests(t *testing.T) {
	req := browserRequest("authserver_device", thisDevice)

	device := NewDeviceCookie(false).read(req)

	wantName, wantType, wantOS := useragent.Labels(req)
	assert.Equal(t, wantName, device.Name)
	assert.Equal(t, wantType, device.Type)
	assert.Equal(t, wantOS, device.OS)
	assert.NotEmpty(t, device.Name)
	assert.Equal(t, chromeUserAgent, device.UserAgent)
}
