package usersession

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/hashutil"
)

// The device cookie names a browser rather than a session, so that a sign-in can tell the user's
// earlier sessions from this browser from those of another browser sending the same User-Agent
// from the same address (#564 decision 4). It is first-party and read by the auth server alone, and
// used only to end that user's own earlier sessions from the same browser.
const (
	// deviceCookieName is the cookie's name on plain http. On https it carries the __Host- prefix,
	// which a browser accepts only on a Secure, host-only cookie with Path=/, so a sibling
	// subdomain cannot plant a value (RFC 6265bis section 4.1.3.2), as on the session cookie (#266).
	deviceCookieName = "authserver_device"
	hostCookiePrefix = "__Host-"

	// deviceCookieMaxAge is 400 days, the longest RFC 6265bis lets a browser keep a cookie.
	deviceCookieMaxAge = 400 * 24 * 60 * 60

	// deviceIdBytes is how many bytes of the CSPRNG an identifier holds, hex encoded in the cookie.
	deviceIdBytes = 32
)

func (u *Manager) deviceCookieName() string {
	if u.secureCookies {
		return hostCookiePrefix + deviceCookieName
	}
	return deviceCookieName
}

// browserDevice is the device identifier the browser presents, or a new one when it presents none
// or one that does not parse. Only the name this deployment writes is read, so on https a bare-named
// cookie, which a sibling host could have set, is not.
func (u *Manager) browserDevice(r *http.Request) (string, error) {
	if cookie, err := r.Cookie(u.deviceCookieName()); err == nil && isDeviceIdentifier(cookie.Value) {
		return cookie.Value, nil
	}
	buf := make([]byte, deviceIdBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", errs.Wrap(err, "unable to read from the random number generator")
	}
	return hex.EncodeToString(buf), nil
}

// isDeviceIdentifier is whether value is one this server mints: deviceIdBytes as lower-case hex. A
// browser cannot choose its identifier beyond presenting one it was given.
func isDeviceIdentifier(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == deviceIdBytes && hex.EncodeToString(decoded) == value
}

// deviceDigest is what a session stores of the identifier: its SHA-256, so a database read does not
// hand out a value a browser could present.
func deviceDigest(identifier string) string {
	return hashutil.HashString(identifier)
}

// writeDeviceCookie gives the browser its identifier for another 400 days, with the session
// cookie's attributes.
func (u *Manager) writeDeviceCookie(w http.ResponseWriter, identifier string) {
	//nolint:gosec // G124: HttpOnly and SameSite are set; Secure follows the base URL's scheme, as on the session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     u.deviceCookieName(),
		Value:    identifier,
		Path:     "/",
		MaxAge:   deviceCookieMaxAge,
		HttpOnly: true,
		Secure:   u.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}
