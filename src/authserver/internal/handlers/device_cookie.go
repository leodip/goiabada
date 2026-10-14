package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/useragent"
	"github.com/leodip/goiabada/authserver/internal/usersession"
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

// DeviceCookie reads and writes the device cookie /auth/completed's create arm records a new user
// session with. The route table builds one; secure is whether the auth server's base URL is https,
// which gives the cookie its __Host- prefix and Secure, as it gives them to the session cookie.
type DeviceCookie struct {
	secure bool
}

// NewDeviceCookie builds the device cookie for a deployment whose base URL is https when secure.
func NewDeviceCookie(secure bool) *DeviceCookie {
	return &DeviceCookie{secure: secure}
}

func (d *DeviceCookie) name() string {
	if d.secure {
		return hostCookiePrefix + deviceCookieName
	}
	return deviceCookieName
}

// read is the browser r comes from: the identifier its device cookie holds, or a new one when it
// presents none or one that does not parse, with the display labels and the raw User-Agent. Only the
// name this deployment writes is read, so on https a bare-named cookie, which a sibling host could
// have set, is not.
func (d *DeviceCookie) read(r *http.Request) usersession.Device {
	name, deviceType, deviceOS := useragent.Labels(r)
	device := usersession.Device{Name: name, Type: deviceType, OS: deviceOS, UserAgent: r.UserAgent()}

	if cookie, err := r.Cookie(d.name()); err == nil && isDeviceIdentifier(cookie.Value) {
		device.Identifier = cookie.Value
		return device
	}
	buf := make([]byte, deviceIdBytes)
	_, _ = rand.Read(buf) // cannot fail: crypto/rand ends the process rather than return an error
	device.Identifier = hex.EncodeToString(buf)
	device.New = true
	return device
}

// isDeviceIdentifier is whether value has the shape this server mints: deviceIdBytes as lower-case
// hex. Only the shape is checked, so a browser can present any such value, which is why the
// identifier only ever ends that user's own earlier sessions (#564).
func isDeviceIdentifier(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == deviceIdBytes && hex.EncodeToString(decoded) == value
}

// write gives the browser identifier for another 400 days, with the session cookie's attributes.
func (d *DeviceCookie) write(w http.ResponseWriter, identifier string) {
	//nolint:gosec // G124: HttpOnly and SameSite are set; Secure follows the base URL's scheme, as on the session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     d.name(),
		Value:    identifier,
		Path:     "/",
		MaxAge:   deviceCookieMaxAge,
		HttpOnly: true,
		Secure:   d.secure,
		SameSite: http.SameSiteLaxMode,
	})
}
