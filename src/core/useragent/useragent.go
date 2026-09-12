// Package useragent derives the three display labels a session row carries, and bounds a raw
// User-Agent header to the width of the columns that store it.
//
// The labels are display only. StartNewUserSession keys its "same device" sweep on the raw
// header and the IP address, never on a label, so a label that is wrong costs a person one
// confusing row on a list of their own sessions and nothing else (#281). That is what makes
// the ordered token list below acceptable: it is allowed to be wrong, and it must not grow
// into a database of browser strings, which is the treadmill that replacing a third-party
// parser with a hand-written one exists to leave.
package useragent

import (
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"
)

// The widths of user_sessions.device_name, device_type and device_os. Each label is cut to
// its own column, so a long brand name cannot push the row's insert over a width.
const (
	deviceNameMaxLen = 256
	deviceTypeMaxLen = 32
	deviceOSMaxLen   = 64
)

// Labels derives the browser name with its major version, the device type, and the platform,
// from one request and in one parse.
//
// Client Hints first, the User-Agent second (decision 2 of #281). Chromium freezes its
// User-Agent -- Windows 11 still reports "Windows NT 10.0", every Android phone reports
// "Android 10; K", and the minor version digits are zeroed -- so for the majority browser the
// Sec-CH-UA* headers are the only truthful platform source. They also arrive from nothing but
// Chromium and only in a secure context, so the User-Agent path is the whole story for
// Firefox, Safari, plain-HTTP deployments and every non-browser client, and is not optional.
//
// The three functions this replaced each parsed the header again, so one request was parsed
// three times to fill three columns of one row.
func Labels(r *http.Request) (name, deviceType, os string) {
	name, deviceType, os = derive(r)
	return Bound(name, deviceNameMaxLen), Bound(deviceType, deviceTypeMaxLen), Bound(os, deviceOSMaxLen)
}

func derive(r *http.Request) (name, deviceType, os string) {
	brands, ok := parseBrands(r.Header.Get("Sec-CH-UA"))
	if !ok {
		return fromUserAgent(r.UserAgent())
	}

	b := pickBrand(brands)
	// UA-CH 3.7 declares Sec-CH-UA-Mobile a boolean, so the only value meaning "mobile" is
	// "?1"; "?0", an absent header and anything that is not a boolean at all all mean the
	// device is not a phone. The hints carry no tablet signal of any kind, so Tablet can
	// only ever come from the User-Agent path (decision 3).
	deviceType = "Desktop"
	if r.Header.Get("Sec-CH-UA-Mobile") == "?1" {
		deviceType = "Mobile"
	}
	return strings.TrimSpace(b.name + " " + b.major), deviceType, platform(r.Header.Get("Sec-CH-UA-Platform"))
}

// --- Sec-CH-UA: an sf-list of sf-strings, each with an optional v parameter (UA-CH 3.1).

type brand struct{ name, major string }

// parseBrands reads the header as an RFC 8941 sf-list whose members are sf-strings with
// parameters, and answers false for anything that does not parse.
//
// A refusal here is not an error: RFC 8942 2.2 says a server "MUST ignore hints they do not
// understand nor support", so a header that is not a structured field is treated exactly as
// an absent one and the caller falls through to the User-Agent. Being strict is therefore
// free, and it is the only way a header half-read cannot become a label: without the gates
// below, a brand written Chro\me would have been stored as the browser name Chro\me.
func parseBrands(h string) ([]brand, bool) {
	var out []brand
	i := skipOWS(h, 0)
	if i == len(h) {
		return nil, false
	}
	for {
		name, next, ok := parseString(h, i)
		if !ok {
			return nil, false
		}
		i = next
		major := ""
		for i < len(h) && h[i] == ';' {
			key, value, next, ok := parseParam(h, i+1)
			if !ok {
				return nil, false
			}
			i = next
			// UA-CH 3.1: the v parameter carries the version, of which only the text
			// before the first "." is displayed (decision 3). A brand sending the full
			// version and one sending the major alone therefore read the same.
			if key == "v" {
				major, _, _ = strings.Cut(value, ".")
			}
		}
		out = append(out, brand{name, major})
		i = skipOWS(h, i)
		if i == len(h) {
			return out, true
		}
		// A member is its string, then its parameters, then a comma or the end of the
		// field. Anything else is not an sf-list (RFC 8941 3.1), and a reader that
		// skipped to the next comma instead would silently accept a truncated header.
		if h[i] != ',' {
			return nil, false
		}
		i = skipOWS(h, i+1)
	}
}

// parseString reads one RFC 8941 3.3.3 sf-string at s[i], returning its unescaped value and
// the index just past its closing quote. Three ways it refuses, each of them that section
// read as written: an escape of anything but a quote or a backslash, since "other characters
// after \ MUST cause parsing to fail"; an unescaped byte outside
// unescaped = %x20-21 / %x23-5B / %x5D-7E; and a string that never closes.
func parseString(s string, i int) (string, int, bool) {
	if i >= len(s) || s[i] != '"' {
		return "", 0, false
	}
	i++
	var b strings.Builder
	for i < len(s) {
		switch c := s[i]; {
		case c == '\\':
			if i+1 >= len(s) || (s[i+1] != '"' && s[i+1] != '\\') {
				return "", 0, false
			}
			b.WriteByte(s[i+1])
			i += 2
		case c == '"':
			return b.String(), i + 1, true
		case c < 0x20 || c > 0x7e:
			return "", 0, false
		default:
			b.WriteByte(c)
			i++
		}
	}
	return "", 0, false
}

// parseParam reads one ";"-led parameter, i pointing just past the semicolon. A parameter
// with no "=" is boolean true (RFC 8941 3.1.2) and is read as valueless here, because the
// only key this package looks at is v.
func parseParam(h string, i int) (key, value string, next int, ok bool) {
	i = skipOWS(h, i)
	start := i
	for i < len(h) && isTokenChar(h[i]) {
		i++
	}
	if i == start {
		return "", "", 0, false
	}
	key = h[start:i]
	if i == len(h) || h[i] != '=' {
		return key, "", i, true
	}
	i++
	if i < len(h) && h[i] == '"' {
		v, next, ok := parseString(h, i)
		if !ok {
			return "", "", 0, false
		}
		return key, v, next, true
	}
	start = i
	for i < len(h) && h[i] != ';' && h[i] != ',' && h[i] != ' ' {
		i++
	}
	return key, h[start:i], i, true
}

func skipOWS(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

func isTokenChar(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
		strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

// platform reads Sec-CH-UA-Platform through the same sf-string reader, so an unquoted value,
// an invalid escape or anything trailing the closing quote leaves the platform absent rather
// than half read. "Unknown" is one of the values UA-CH 3.9 lists and means absent here.
func platform(h string) string {
	p, next, ok := parseString(h, skipOWS(h, 0))
	if !ok || skipOWS(h, next) != len(h) || p == "Unknown" {
		return ""
	}
	return p
}

// GREASE brands are arbitrary by design: UA-CH 8.2 requires a user agent to include "an
// arbitrary value" among its brands and to change their order over time, precisely so a
// server cannot rely on a brand sitting in a known position. Chromium's arbitrary entry has
// always been "Not" and "Brand" around two punctuation characters, and nothing else is
// assumed about it -- a GREASE brand that stops matching this is picked as a real brand,
// which shows up as an odd name on a session list and costs nothing else.
var grease = regexp.MustCompile(`(?i)^not.*brand$`)

// Two brands name one product under a vendor prefix. Stripping the prefix is what makes the
// hints path and the User-Agent path agree: the same Chrome reads "Chrome 120" either way.
var brandDisplay = map[string]string{"Google Chrome": "Chrome", "Microsoft Edge": "Edge"}

// pickBrand takes the first brand that is neither GREASE nor Chromium, because every
// Chromium fork sends both its own brand and "Chromium" and the fork is the interesting one.
// Chromium itself is the answer when there is no fork (headless Chrome, Electron), and the
// first brand as sent when every brand looked like GREASE, so a session is never labelled
// from nothing.
func pickBrand(bs []brand) brand {
	var chromium *brand
	for i := range bs {
		b := bs[i]
		if grease.MatchString(b.name) {
			continue
		}
		if b.name == "Chromium" {
			chromium = &bs[i]
			continue
		}
		if d, ok := brandDisplay[b.name]; ok {
			b.name = d
		}
		return b
	}
	if chromium != nil {
		return *chromium
	}
	return bs[0]
}

// --- The User-Agent fallback: ordered substring checks.
//
// Order is the whole trick, and the reason this is a list rather than a set: every Chromium
// fork names Chrome, and Safari's version lives in a token Chrome sends too, so Edge is read
// before Chrome and Chrome before Safari. First hit wins.
//
// This list is fixed and stays short. It is allowed to be wrong -- a browser it does not know
// falls through to its first product token, which is a worse label and not a broken one --
// and growing it into an exhaustive table is the treadmill this package exists to leave.
var browserOrder = []struct{ token, display string }{
	{"Edg/", "Edge"}, {"OPR/", "Opera"}, {"Firefox/", "Firefox"}, {"FxiOS/", "Firefox"},
	{"CriOS/", "Chrome"}, {"Chrome/", "Chrome"}, {"Version/", "Safari"},
}

// Ordered for the same reason: an Android User-Agent also says "Linux", and a Chrome OS one
// says neither until "CrOS" is read. No version is kept (decision 3), because Chromium's is
// frozen and the two paths have to agree.
var osOrder = []struct{ token, display string }{
	{"Windows", "Windows"}, {"Android", "Android"}, {"CrOS", "Chrome OS"},
	{"iPhone", "iOS"}, {"iPad", "iOS"}, {"Mac OS X", "macOS"}, {"Linux", "Linux"},
}

// RFC 9110 5.6.2 token characters; product = token ["/" product-version] (10.1.5).
const tchar = "[!#$%&'*+.^_`|~0-9A-Za-z-]+"

var product = regexp.MustCompile("^(" + tchar + ")(?:/(" + tchar + "))?")

// majorAfter reads the version digits following token, up to the first "." or the end of the
// product token. The caller has already established that ua contains token.
func majorAfter(ua, token string) string {
	i := strings.Index(ua, token)
	rest := ua[i+len(token):]
	end := strings.IndexAny(rest, " ;)")
	if end < 0 {
		end = len(rest)
	}
	major, _, _ := strings.Cut(rest[:end], ".")
	return major
}

func fromUserAgent(ua string) (name, deviceType, os string) {
	name, deviceType, os = "Unknown", "unknown", ""
	if strings.TrimSpace(ua) == "" {
		return name, deviceType, os
	}

	found := false
	for _, b := range browserOrder {
		if !strings.Contains(ua, b.token) {
			continue
		}
		// "Version/" is Safari's version only when the header also claims Safari; every
		// other product that sends it has already matched its own token above.
		if b.display == "Safari" && !strings.Contains(ua, "Safari/") {
			continue
		}
		name = strings.TrimSpace(b.display + " " + majorAfter(ua, b.token))
		found = true
		break
	}
	if !found {
		// No browser recognised: the first RFC 9110 product token with its version, which
		// is what keeps "curl 8.5.0" and "Go-http-client 1.1" reading as themselves rather
		// than collapsing to one label -- and what keeps the integration fixtures that
		// fake a second device with an invented token telling themselves apart. A header
		// opening with a comment matches no product and stays "Unknown".
		if m := product.FindStringSubmatch(ua); m != nil {
			name = strings.TrimSpace(m[1] + " " + m[2])
		}
	}

	for _, o := range osOrder {
		if strings.Contains(ua, o.token) {
			os = o.display
			break
		}
	}

	switch {
	// An iPad says "iPad", and an Android tablet is an Android that does not say "Mobile",
	// which is Google's own rule for the frozen string. Current iPadOS Safari sends a
	// desktop macOS User-Agent and is labelled a macOS desktop: that is the browser's own
	// choice, which RFC 9110 10.1.5 says recipients are to take at face value.
	case strings.Contains(ua, "iPad"), strings.Contains(ua, "Android") && !strings.Contains(ua, "Mobile"):
		deviceType = "Tablet"
	case strings.Contains(ua, "Mobile"), strings.Contains(ua, "iPhone"):
		deviceType = "Mobile"
	// A recognised OS and no mobile signal is a desktop. No OS at all leaves the type
	// unknown, which is where curl, Go's client and the integration fixtures land.
	case os != "":
		deviceType = "Desktop"
	}
	return name, deviceType, os
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
