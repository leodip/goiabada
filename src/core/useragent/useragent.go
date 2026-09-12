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
	"encoding/base64"
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
		// field. Anything else is not an sf-list (RFC 9651 3.1), and a reader that
		// skipped to the next comma instead would silently accept a truncated header.
		if h[i] != ',' {
			return nil, false
		}
		i = skipOWS(h, i+1)
	}
}

// parseString reads one RFC 9651 3.3.3 sf-string at s[i], returning its unescaped value and
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

// parseParam reads one ";"-led parameter, i pointing just past the semicolon, per RFC 9651
// 3.1.2: parameters = *( ";" *SP parameter ), parameter = param-key [ "=" param-value ],
// param-value = bare-item. A parameter with no "=" is boolean true and is read as valueless
// here, because the only key this package looks at is v.
//
// Both halves are the structured-field grammar and not the wider HTTP one, which is what makes
// parseBrands's promise -- a header that does not parse is treated as absent -- true rather
// than nearly true. A key is lowercase (RFC 9651's key production), so "V" is not "v" written
// differently, it is not a key at all; and a value is a bare item, so v=@junk is a malformed
// header rather than the version "@junk". Reading either loosely accepts a Sec-CH-UA that no
// structured-field parser would, and then labels the session from it, when RFC 8942 2.2 says a
// hint a server cannot understand is one to ignore in favour of the User-Agent (#281).
func parseParam(h string, i int) (key, value string, next int, ok bool) {
	i = skipSP(h, i)
	start := i
	if i == len(h) || !isKeyStart(h[i]) {
		return "", "", 0, false
	}
	for i < len(h) && isKeyChar(h[i]) {
		i++
	}
	key = h[start:i]
	if i == len(h) || h[i] != '=' {
		return key, "", i, true
	}
	value, next, ok = parseBareItem(h, i+1)
	if !ok {
		return "", "", 0, false
	}
	return key, value, next, true
}

// parseBareItem reads one RFC 9651 3.3 bare item and answers its text as sent, together with
// the index just past it.
//
// RFC 9651 rather than RFC 8941, which it obsoletes: UA-CH 3.1, 3.7 and 3.9 now define all
// three hints against 9651, and 4.2.3.1 there dispatches on eight leading characters rather
// than six, "@" starting a Date (3.3.7) and "%" a Display String (3.3.8). Reading the older
// set refuses those two forms, and since a refusal means "fall back to the User-Agent", a
// valid current field would have been answered with a label derived from a header Chromium
// freezes -- the exact outcome decision 2 of #281 exists to avoid.
//
// Only the v parameter is ever looked at and UA-CH 3.1 says its value is a String, so the
// other seven forms are here to be recognised rather than to be used: a header carrying a
// well-formed integer or token parameter is a valid structured field, and RFC 8942 2.2 asks
// that such a hint be honoured rather than refused for spelling a value in a form this
// package happens not to read.
//
// Every form but the string answers the source text as sent rather than a decoded value, and
// for the Display String that is load-bearing rather than merely consistent: 4.2.10 rejects
// anything outside VCHAR and SP in the *encoded* text but places no limit on what the
// pct-encoded octets decode to, so %"%00" is a valid field whose value is a NUL byte.
// Answering the span keeps every byte that can reach a label inside VCHAR and SP, which is
// what it was before this form was recognised at all -- and PostgreSQL refuses a text value
// carrying U+0000 outright, so a decoded value could have failed the session insert.
func parseBareItem(s string, i int) (string, int, bool) {
	if i >= len(s) {
		return "", 0, false
	}
	switch c := s[i]; {
	case c == '"':
		return parseString(s, i)
	case c == '?':
		// sf-boolean = "?" ( "0" / "1" ).
		if i+1 < len(s) && (s[i+1] == '0' || s[i+1] == '1') {
			return s[i : i+2], i + 2, true
		}
		return "", 0, false
	case c == ':':
		return parseByteSequence(s, i)
	case c == '@':
		return parseDate(s, i)
	case c == '%':
		return parseDisplayString(s, i)
	case c == '-' || isDigit(c):
		return parseNumber(s, i)
	// sf-token = ( ALPHA / "*" ) *( tchar / ":" / "/" ).
	case c == '*' || isAlpha(c):
		start := i
		for i++; i < len(s) && (isTokenChar(s[i]) || s[i] == ':' || s[i] == '/'); i++ {
		}
		return s[start:i], i, true
	}
	return "", 0, false
}

// parseDate reads an RFC 9651 3.3.7 sf-date, "@" followed by an sf-integer. 4.2.9 step 4
// fails parsing when what follows is a Decimal, so the point that parseNumber would have
// accepted is what separates @1659578233 from @1659578233.5 here.
func parseDate(s string, i int) (string, int, bool) {
	n, next, ok := parseNumber(s, i+1)
	if !ok || strings.Contains(n, ".") {
		return "", 0, false
	}
	return s[i:next], next, true
}

// parseDisplayString reads an RFC 9651 3.3.8 sf-displaystring, per the 4.2.10 algorithm:
// %"..." whose body is VCHAR or SP, in which "%" introduces two lowercase hex digits and
// every other character including "\" stands for itself, and whose pct-decoded octets must
// together be valid UTF-8.
//
// The backslash is not an escape here, which is the one place this differs from parseString
// and the reason the two are not shared: 4.2.10's loop appends it like any other character,
// so %"a\"" closes at the quote after the backslash where "a\"" would not.
func parseDisplayString(s string, i int) (string, int, bool) {
	if i+1 >= len(s) || s[i+1] != '"' {
		return "", 0, false
	}
	start := i
	var decoded strings.Builder
	for i += 2; i < len(s); {
		switch c := s[i]; {
		// 4.2.10: "If char is in the range %x00-1f or %x7f-ff [...] fail parsing."
		case c < 0x20 || c >= 0x7f:
			return "", 0, false
		case c == '%':
			if i+2 >= len(s) || !isLCHexDig(s[i+1]) || !isLCHexDig(s[i+2]) {
				return "", 0, false
			}
			decoded.WriteByte(hexVal(s[i+1])<<4 | hexVal(s[i+2]))
			i += 3
		case c == '"':
			if !utf8.ValidString(decoded.String()) {
				return "", 0, false
			}
			return s[start : i+1], i + 1, true
		default:
			decoded.WriteByte(c)
			i++
		}
	}
	return "", 0, false
}

// parseNumber reads an RFC 9651 3.3.1 sf-integer or 3.3.2 sf-decimal. The digit counts are the
// grammar's own -- at most 15 integer digits, or at most 12 before the point and one to three
// after it -- and they are the whole difference between a bare item and a run of digits.
func parseNumber(s string, i int) (string, int, bool) {
	// Bounds-checked here rather than at the callers, because the two of them reach it
	// differently: parseBareItem has already read s[i] and cannot be past the end, while
	// parseDate steps over an "@" that may have been the last byte of the field. A reader
	// that leaves this to the caller is one new caller away from panicking on a header
	// anyone can send (#281).
	if i >= len(s) {
		return "", 0, false
	}
	start := i
	if s[i] == '-' {
		i++
	}
	digits := i
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	whole := i - digits
	if whole == 0 {
		return "", 0, false
	}
	if i == len(s) || s[i] != '.' {
		if whole > 15 {
			return "", 0, false
		}
		return s[start:i], i, true
	}
	if whole > 12 {
		return "", 0, false
	}
	i++
	frac := i
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	if n := i - frac; n < 1 || n > 3 {
		return "", 0, false
	}
	return s[start:i], i, true
}

// parseByteSequence reads an RFC 9651 3.3.5 sf-binary, base64 between two colons. The value is
// returned with its colons, since nothing reads it: what matters is that a well-formed one
// parses, and that an unterminated one does not swallow the rest of the field.
//
// The alphabet check of 4.2.7 step 6 is not the whole gate, and reading it as though it were
// is the easy mistake: step 7 then requires the content to be base64-decoded and says "if
// base64 decoding fails, parsing fails". A run of alphabet characters need not decode -- :A:
// is six bits, which is no whole byte, and :=A==: spells padding where content belongs -- so
// without the decode a malformed hint parses, and parseBrands's promise that a field either
// parses or is ignored in favour of the User-Agent (RFC 8942 2.2) would hold for every form
// but this one.
//
// Padding is synthesized rather than demanded, which is what step 7 asks for: the trailing
// "=" are dropped and the rest decoded unpadded, so :QQ: and :QQ==: are the same byte and an
// "=" anywhere but the end is still refused.
func parseByteSequence(s string, i int) (string, int, bool) {
	start := i
	for i++; i < len(s) && s[i] != ':'; i++ {
		if !isBase64Char(s[i]) {
			return "", 0, false
		}
	}
	if i == len(s) {
		return "", 0, false
	}
	if _, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(s[start+1:i], "=")); err != nil {
		return "", 0, false
	}
	return s[start : i+1], i + 1, true
}

// OWS is what RFC 9651 4.2.1 discards around the commas of a list, and the only place in this
// reader where a tab is whitespace rather than a parse failure.
func skipOWS(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

// RFC 9651 3.1.2 separates a parameter from the ";" before it with *SP, not OWS: a tab there
// is not whitespace to skip, it is a header that does not parse. 4.2's own step 2 and step 6,
// which bracket the whole field, are *SP too.
func skipSP(s string, i int) int {
	for i < len(s) && s[i] == ' ' {
		i++
	}
	return i
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func isTokenChar(c byte) bool {
	return isDigit(c) || isAlpha(c) || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

// RFC 9651 3.1.2: key = ( lcalpha / "*" ) *( lcalpha / DIGIT / "_" / "-" / "." / "*" ).
func isKeyStart(c byte) bool { return c >= 'a' && c <= 'z' || c == '*' }

func isKeyChar(c byte) bool {
	return c >= 'a' && c <= 'z' || isDigit(c) || strings.IndexByte("_-.*", c) >= 0
}

func isBase64Char(c byte) bool {
	return isDigit(c) || isAlpha(c) || c == '+' || c == '/' || c == '='
}

// RFC 9651 3.3.8: pct-encoded = "%" lc-hexdig lc-hexdig, lc-hexdig = DIGIT / %x61-66. Upper
// case is not the same digit spelled differently, it is a field that does not parse.
func isLCHexDig(c byte) bool { return isDigit(c) || (c >= 'a' && c <= 'f') }

func hexVal(c byte) byte {
	if isDigit(c) {
		return c - '0'
	}
	return c - 'a' + 10
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
