package useragent

// The RFC 9651 structured-field grammar the Client Hints are read with: the bare items, the
// parameters and the whitespace rules parseBrands and platform build on. Every reader here
// answers false for anything the grammar does not produce, because a hint that does not parse
// is ignored in favour of the User-Agent (RFC 8942 2.2) rather than half read into a label.

import (
	"encoding/base64"
	"strings"
	"unicode/utf8"
)

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
//
// isString is the bare item's type, carried out because the one parameter this package reads
// is defined as a String and every other type is a valid parameter whose value is unusable.
// A valueless parameter is boolean true (RFC 9651 3.1.2), so it is not a string either.
func parseParam(h string, i int) (key, value string, isString bool, next int, ok bool) {
	i = skipSP(h, i)
	start := i
	if i == len(h) || !isKeyStart(h[i]) {
		return "", "", false, 0, false
	}
	for i < len(h) && isKeyChar(h[i]) {
		i++
	}
	key = h[start:i]
	if i == len(h) || h[i] != '=' {
		return key, "", false, i, true
	}
	value, isString, next, ok = parseBareItem(h, i+1)
	if !ok {
		return "", "", false, 0, false
	}
	return key, value, isString, next, true
}

// parseBareItem reads one RFC 9651 3.3 bare item, answering the index just past it, whether it
// was a String, and its value when it was one.
//
// RFC 9651 rather than RFC 8941, which it obsoletes: UA-CH 3.1, 3.7 and 3.9 now define all
// three hints against 9651, and 4.2.3.1 there dispatches on eight leading characters rather
// than six, "@" starting a Date (3.3.7) and "%" a Display String (3.3.8). Reading the older
// set refuses those two forms, and since a refusal means "fall back to the User-Agent", a
// valid current field would have been answered with a label derived from a header Chromium
// freezes -- the exact outcome decision 2 of #281 exists to avoid.
//
// The other seven forms are recognised rather than read, and answer no value at all. The one
// parameter this package looks at is v, which UA-CH 4.1.4 defines as a string, so no other
// type can be a version; and a header carrying a well-formed integer or token parameter on any
// key is still a valid structured field, which RFC 8942 2.2 asks be honoured rather than
// refused for spelling a value in a form this package does not read. Answering nothing for
// them is what keeps those two facts from colliding: before this, every form answered its
// source span and "v=@1659578233" was displayed as the version "@1659578233".
//
// It also settles the Display String, which is the form where answering a value is genuinely
// unsafe: 4.2.10 rejects anything outside VCHAR and SP in the *encoded* text but places no
// limit on what the pct-encoded octets decode to, so %"%00" is a valid field whose value is a
// NUL byte, and PostgreSQL refuses a text value carrying U+0000 outright. A form that answers
// no value cannot put one in a label or in a column.
func parseBareItem(s string, i int) (value string, isString bool, next int, ok bool) {
	if i >= len(s) {
		return "", false, 0, false
	}
	switch c := s[i]; {
	case c == '"':
		v, next, ok := parseString(s, i)
		if !ok {
			return "", false, 0, false
		}
		return v, true, next, true
	case c == '?':
		// sf-boolean = "?" ( "0" / "1" ).
		if i+1 < len(s) && (s[i+1] == '0' || s[i+1] == '1') {
			return "", false, i + 2, true
		}
		return "", false, 0, false
	case c == ':':
		next, ok := parseByteSequence(s, i)
		return "", false, next, ok
	case c == '@':
		next, ok := parseDate(s, i)
		return "", false, next, ok
	case c == '%':
		next, ok := parseDisplayString(s, i)
		return "", false, next, ok
	case c == '-' || isDigit(c):
		_, next, ok := parseNumber(s, i)
		return "", false, next, ok
	// sf-token = ( ALPHA / "*" ) *( tchar / ":" / "/" ).
	case c == '*' || isAlpha(c):
		for i++; i < len(s) && (isTokenChar(s[i]) || s[i] == ':' || s[i] == '/'); i++ {
		}
		return "", false, i, true
	}
	return "", false, 0, false
}

// parseDate reads an RFC 9651 3.3.7 sf-date, "@" followed by an sf-integer. 4.2.9 step 4
// fails parsing when what follows is a Decimal, so the point that parseNumber would have
// accepted is what separates @1659578233 from @1659578233.5 here.
func parseDate(s string, i int) (int, bool) {
	n, next, ok := parseNumber(s, i+1)
	if !ok || strings.Contains(n, ".") {
		return 0, false
	}
	return next, true
}

// parseDisplayString reads an RFC 9651 3.3.8 sf-displaystring, per the 4.2.10 algorithm:
// %"..." whose body is VCHAR or SP, in which "%" introduces two lowercase hex digits and
// every other character including "\" stands for itself, and whose pct-decoded octets must
// together be valid UTF-8.
//
// The backslash is not an escape here, which is the one place this differs from parseString
// and the reason the two are not shared: 4.2.10's loop appends it like any other character,
// so %"a\"" closes at the quote after the backslash where "a\"" would not.
func parseDisplayString(s string, i int) (int, bool) {
	if i+1 >= len(s) || s[i+1] != '"' {
		return 0, false
	}
	var decoded strings.Builder
	for i += 2; i < len(s); {
		switch c := s[i]; {
		// 4.2.10: "If char is in the range %x00-1f or %x7f-ff [...] fail parsing."
		case c < 0x20 || c >= 0x7f:
			return 0, false
		case c == '%':
			if i+2 >= len(s) || !isLCHexDig(s[i+1]) || !isLCHexDig(s[i+2]) {
				return 0, false
			}
			decoded.WriteByte(hexVal(s[i+1])<<4 | hexVal(s[i+2]))
			i += 3
		case c == '"':
			if !utf8.ValidString(decoded.String()) {
				return 0, false
			}
			return i + 1, true
		default:
			decoded.WriteByte(c)
			i++
		}
	}
	return 0, false
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

// parseByteSequence reads an RFC 9651 3.3.5 sf-binary, base64 between two colons, and answers
// no value: what matters is that a well-formed one parses, and that an unterminated one does
// not swallow the rest of the field.
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
func parseByteSequence(s string, i int) (int, bool) {
	start := i
	for i++; i < len(s) && s[i] != ':'; i++ {
		if !isBase64Char(s[i]) {
			return 0, false
		}
	}
	if i == len(s) {
		return 0, false
	}
	if _, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(s[start+1:i], "=")); err != nil {
		return 0, false
	}
	return i + 1, true
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
