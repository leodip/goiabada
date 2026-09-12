package useragent

import (
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/mileusna/useragent"
)

func GetDeviceName(r *http.Request) string {
	var deviceName string
	deviceNameMaxLen := 256
	ua := useragent.Parse(r.Header.Get("User-Agent"))
	if len(ua.Device) > 0 {
		deviceName = fmt.Sprintf("%v %v (%v)", ua.Name, ua.Version, ua.Device)
	} else {
		deviceName = fmt.Sprintf("%v %v", ua.Name, ua.Version)
	}

	if len(deviceName) > deviceNameMaxLen {
		deviceName = deviceName[:deviceNameMaxLen]
	}

	return deviceName
}

func GetDeviceType(r *http.Request) string {
	ua := useragent.Parse(r.Header.Get("User-Agent"))
	t := "unknown"

	switch {
	case ua.Mobile:
		t = "Mobile"
	case ua.Tablet:
		t = "Tablet"
	case ua.Desktop:
		t = "Desktop"
	case ua.Bot:
		t = "Bot"
	}

	return t
}

func GetDeviceOS(r *http.Request) string {
	deviceOSMaxLen := 64
	ua := useragent.Parse(r.Header.Get("User-Agent"))
	deviceOS := fmt.Sprintf("%v %v", ua.OS, ua.OSVersion)

	if len(deviceOS) > deviceOSMaxLen {
		deviceOS = deviceOS[:deviceOSMaxLen]
	}

	return deviceOS
}

// Bound repairs s to valid UTF-8, replacing every invalid byte with U+FFFD, then cuts
// it to at most max bytes on a rune boundary so the result is always valid UTF-8.
//
// The bound is in bytes rather than runes because one byte bound satisfies every engine
// at once: PostgreSQL and MySQL count characters, and a value of at most N bytes has at
// most N characters; SQL Server's nvarchar counts UTF-16 units, and a 4-byte rune is two
// of them, so at most N bytes is at most N units too. Counting runes instead would let a
// 512-rune value of 3-byte runes reach 1536 bytes and be refused by all three.
//
// The repair runs before the cut, never after: PostgreSQL and MySQL both refuse a value
// carrying a stray latin1 byte outright rather than storing it (RFC 9110 10.1.5 allows
// obs-text in a User-Agent), and repairing after the cut would push the result back over
// the bound, since U+FFFD is three bytes where the byte it replaces was one (#281).
func Bound(s string, max int) string {
	s = strings.ToValidUTF8(s, "�")
	if len(s) <= max {
		return s
	}

	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}

	return s[:cut]
}

// Raw is the request's User-Agent header as sent, bounded to the 512 bytes that
// user_sessions.user_agent and codes.user_agent are declared with. It is the key of the
// "same device" sweep together with the IP address, so it is stored rather than parsed:
// a parser's guess at a browser name changes shape whenever the parser is replaced, and
// the sweep then stops recognising a device it recognised yesterday (#281).
func Raw(r *http.Request) string {
	return Bound(r.UserAgent(), 512)
}
