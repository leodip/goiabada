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

// userAgentMaxLen is the width of user_sessions.user_agent and codes.user_agent, the two
// columns a raw header is stored in. BoundRaw is the only reader, so no caller chooses it.
const userAgentMaxLen = 512

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
	return bound(name, deviceNameMaxLen), bound(deviceType, deviceTypeMaxLen), bound(os, deviceOSMaxLen)
}

func derive(r *http.Request) (name, deviceType, os string) {
	brands, ok := parseBrands(fieldValue(r.Header, "Sec-CH-UA"))
	if !ok {
		return fromUserAgent(r.UserAgent())
	}

	b := pickBrand(brands)
	// UA-CH 3.7 declares Sec-CH-UA-Mobile a boolean, so the only value meaning "mobile" is
	// "?1"; "?0", an absent header and anything that is not a boolean at all all mean the
	// device is not a phone. The hints carry no tablet signal of any kind, so Tablet can
	// only ever come from the User-Agent path (decision 3).
	deviceType = "Desktop"
	if fieldValue(r.Header, "Sec-CH-UA-Mobile") == "?1" {
		deviceType = "Mobile"
	}
	return strings.TrimSpace(b.name + " " + b.major), deviceType, platform(fieldValue(r.Header, "Sec-CH-UA-Platform"))
}

// fieldValue is the whole of a header field, which is not always its first line.
//
// A sender may split a list-valued field across several field lines (RFC 9110 5.3), and RFC
// 9651 4.2 says a structured field's value is those lines joined with ", " before it is
// parsed. http.Header.Get answers the first line alone, so it would read a split Sec-CH-UA as
// a shorter list than was sent -- picking a GREASE brand as the browser name when the real
// brands were on the second line -- and would read two Sec-CH-UA-Platform lines as the first
// one instead of as the invalid Item they combine into. Joining first makes a repeated Item
// hint fail its own gate and be ignored, which is what RFC 8942 2.2 asks for (#281).
func fieldValue(h http.Header, name string) string {
	return strings.Join(h.Values(name), ", ")
}

// --- Sec-CH-UA: an sf-list of sf-strings, each with an optional v parameter (UA-CH 3.1).

type brand struct{ name, major string }

// parseBrands reads the header as an RFC 9651 sf-list whose members are sf-strings with
// parameters, and answers false for anything that does not parse.
//
// A refusal here is not an error: RFC 8942 2.2 says a server "MUST ignore hints they do not
// understand nor support", so a header that is not a structured field is treated exactly as
// an absent one and the caller falls through to the User-Agent. Being strict is therefore
// free, and it is the only way a header half-read cannot become a label: without the gates
// below, a brand written Chro\me would have been stored as the browser name Chro\me.
func parseBrands(h string) ([]brand, bool) {
	var out []brand
	// RFC 9651 4.2 step 2 discards leading SP, not OWS, before the field type's own parser
	// runs; OWS is what 4.2.1 discards *between* list members. A tab here is therefore a
	// field that does not parse rather than whitespace to step over.
	i := skipSP(h, 0)
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
			key, value, isString, next, ok := parseParam(h, i+1)
			if !ok {
				return nil, false
			}
			i = next
			// UA-CH 3.1: the v parameter carries the version, of which only the text
			// before the first "." is displayed (decision 3). A brand sending the full
			// version and one sending the major alone therefore read the same.
			//
			// Only a String is a version. UA-CH 4.1.4 builds the parameter by setting
			// param_value to version, which step 3 makes "a string", and the
			// NavigatorUABrandVersion it mirrors declares version a DOMString. A v of
			// any other bare-item type is a parameter this package cannot use rather
			// than a version spelled unusually, so the brand keeps its name and loses
			// its version. The assignment is unconditional because parameters are a
			// dictionary (RFC 9651 3.1.2): a repeated v is the later value, including
			// when the later value is the unusable one (#281).
			if key == "v" {
				major = ""
				if isString {
					major, _, _ = strings.Cut(value, ".")
				}
			}
		}
		out = append(out, brand{name, major})
		i = skipOWS(h, i)
		if i == len(h) {
			return out, true
		}
		// A member is its string, then its parameters, then a comma or the end of the
		// field. Anything else is not an sf-list (RFC 9651 3.1), and a reader that
		// skipped to the next comma instead would silently accept a truncated header.
		if h[i] != ',' {
			return nil, false
		}
		i = skipOWS(h, i+1)
	}
}

// platform reads Sec-CH-UA-Platform through the same sf-string reader, so an unquoted value,
// an invalid escape or anything trailing the closing quote leaves the platform absent rather
// than half read. "Unknown" is one of the values UA-CH 3.9 lists and means absent here.
//
// Both edges are *SP and not OWS, per RFC 9651 4.2 steps 2 and 6: an Item has no parser of
// its own that discards OWS the way 4.2.1 does between list members, so the whole of an
// Item field's top-level whitespace is these two sites.
func platform(h string) string {
	p, next, ok := parseString(h, skipSP(h, 0))
	if !ok || skipSP(h, next) != len(h) || p == "Unknown" {
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

// bound repairs s to valid UTF-8, replacing every invalid byte with U+FFFD, then cuts
// it to at most limit bytes on a rune boundary so the result is always valid UTF-8.
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
func bound(s string, limit int) string {
	s = strings.ToValidUTF8(s, "�")
	if len(s) <= limit {
		return s
	}

	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}

	return s[:cut]
}

// BoundRaw is a raw User-Agent header bounded to the 512 bytes that user_sessions.user_agent
// and codes.user_agent are declared with. The header is the key of the "same device" sweep
// together with the IP address, so it is stored rather than parsed: a parser's guess at a
// browser name changes shape whenever the parser is replaced, and the sweep then stops
// recognising a device it recognised yesterday (#281). Both writers of those columns call this,
// so neither chooses the width.
func BoundRaw(s string) string {
	return bound(s, userAgentMaxLen)
}
