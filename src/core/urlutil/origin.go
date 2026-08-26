package urlutil

import "strings"

// CanonicalOrigin returns raw as the exact string a browser sends in an Origin header,
//
//	scheme "://" host [ ":" port ]
//
// lowercased, with a default port dropped and nothing after the authority, and reports false
// when raw cannot be one. CORS compares the stored value to that header byte for byte, so a
// value that is not already in this form can never match and is silently dead once stored
// (#250).
//
// # The asymmetry is the point
//
// It CONVERTS only case, a trailing slash, a path, a query, a fragment, surrounding
// whitespace, and a default port (:80 on http, :443 on https). Everything else a browser
// would serialize differently is REFUSED rather than converted: a non-ASCII host, userinfo,
// any IPv6 literal, a zone identifier, an empty or leading-zero or out-of-range port, and a
// host that ends in an IPv4 number without being a strict dotted quad (http://127.1,
// http://2130706433, http://0x7f000001 all mean 127.0.0.1 to a browser).
//
// That is not conservatism. Migration 000034 repairs the rows stored before this function
// existed, in SQL, on four engines, and SQL cannot do punycode, IPv6 compression or IPv4
// expansion. Converting a shape the migration cannot reach would create a row that is
// permanently dead, which is the defect this whole function exists to remove. So the set the
// write path accepts is exactly the set the repair can reach, and widening one without the
// other reopens the bug (#250).
//
// # Textual, deliberately
//
// Like stripPortRaw, this never parses and re-renders through url.URL. That would lowercase
// the scheme, re-escape the path and drop components on its own initiative, which hides which
// component moved, and which component moved is this function's entire contract. Go's parser
// also disagrees with browsers on the shapes above: it accepts percent-escapes and brackets in
// a host and normalises neither IPv4 nor IDN, so a value it accepted would still not be what a
// browser sends. Do not "simplify" this into a parse-and-render.
//
// The length of the result is not checked here. A cap belongs to whoever stores it, not to
// what an origin is (#250 decision 14b).
func CanonicalOrigin(raw string) (string, bool) {
	// WHATWG URL strips leading and trailing C0 control or space before parsing, so a browser
	// serializes a padded value identically to a bare one. Interior control characters are a
	// different matter: the browser removes tabs and newlines from anywhere in the URL, which
	// would change the host, so those fall to the forbidden-code-point rule below and are
	// refused.
	s := strings.TrimFunc(raw, func(r rune) bool { return r <= ' ' })

	i := strings.Index(s, "://")
	if i < 0 {
		return "", false
	}
	scheme := strings.ToLower(s[:i])
	if scheme != "http" && scheme != "https" {
		return "", false
	}

	authority := s[i+len("://"):]
	if n := strings.IndexAny(authority, "/?#"); n >= 0 {
		authority = authority[:n]
	}
	if authority == "" {
		return "", false
	}
	// Userinfo never appears in an Origin header. It is also a forbidden domain code point, so
	// the host rule would catch it anyway; it is refused by name because decision 14 names it.
	if strings.Contains(authority, "@") {
		return "", false
	}

	host := strings.ToLower(authority)
	port := ""
	hasPort := false
	// The last colon, not the first: a host holding any other colon keeps it and is then
	// refused as a forbidden code point, and an IPv6 literal is refused whichever colon is
	// chosen because the bracket is forbidden too.
	if c := strings.LastIndex(host, ":"); c >= 0 {
		host, port, hasPort = host[:c], host[c+1:], true
	}
	if hasPort && !isCanonicalPort(port) {
		return "", false
	}
	if !isCanonicalHost(host) {
		return "", false
	}

	out := scheme + "://" + host
	// A browser omits the default port, so storing it is storing a value the header never
	// carries.
	if hasPort && !((scheme == "http" && port == "80") || (scheme == "https" && port == "443")) {
		out += ":" + port
	}
	return out, true
}

// isCanonicalPort reports whether port is the exact decimal a browser would serialize: no
// leading zero, no emptiness, and inside the range the WHATWG URL port parser accepts.
// "0443" and "" both mean 443 and "" to a browser respectively, which is a different string
// from the one an administrator typed, so both are refused rather than converted.
func isCanonicalPort(port string) bool {
	if port == "" || len(port) > 5 || !isDigits(port) {
		return false
	}
	if len(port) > 1 && port[0] == '0' {
		return false
	}
	n := 0
	for i := 0; i < len(port); i++ {
		n = n*10 + int(port[i]-'0')
	}
	return n <= 65535
}

// isCanonicalHost reports whether host, already lowercased, is what a browser would serialize
// for itself.
//
// Two rules. Every byte must be an allowed domain code point, which is printable ASCII minus
// WHATWG URL's forbidden domain code points; that single test is what refuses a non-ASCII host
// (it would become punycode), every IPv6 literal and zone identifier (brackets and percent), a
// backslash path separator, and any percent-escape. And a host that ends in an IPv4 number is
// re-serialized by the browser as a dotted quad, so it is accepted only when it already is
// one.
func isCanonicalHost(host string) bool {
	if host == "" {
		return false
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		// Excludes C0 controls, space, DEL and every non-ASCII byte in one comparison.
		if c <= ' ' || c >= 0x7f {
			return false
		}
		switch c {
		case '#', '/', ':', '<', '>', '?', '@', '[', '\\', ']', '^', '|', '%':
			return false
		}
	}

	labels := strings.Split(host, ".")
	// A single trailing dot is a distinct host a browser serializes verbatim, so it is kept.
	// It is not part of the name for the purpose of deciding whether the host ends in a
	// number.
	last := labels[len(labels)-1]
	if last == "" && len(labels) > 1 {
		last = labels[len(labels)-2]
	}
	if endsInIPv4Number(last) {
		// "127.0.0.1." reaches here with last == "1" and is refused: the browser drops the
		// trailing dot when the host parses as IPv4, so it serializes differently.
		return isDottedQuad(host)
	}
	for i, label := range labels {
		if label == "" && !(i > 0 && i == len(labels)-1) {
			return false
		}
	}
	return true
}

// endsInIPv4Number reports whether label makes the WHATWG URL parser treat the whole host as
// an IPv4 address rather than a domain: an all-decimal label, or a hexadecimal one. label is
// already lowercased, so "0X" needs no separate case.
func endsInIPv4Number(label string) bool {
	if label == "" {
		return false
	}
	if isDigits(label) {
		return true
	}
	if !strings.HasPrefix(label, "0x") {
		return false
	}
	for i := len("0x"); i < len(label); i++ {
		c := label[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// isDottedQuad reports whether host is already the form a browser serializes an IPv4 address
// as: exactly four decimal parts, each 0 to 255, none carrying a leading zero. A leading zero
// is octal to the URL parser, so "010.0.0.1" is 8.0.0.1 to a browser and is not the value it
// would send.
func isDottedQuad(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		// isDigits reports true for the empty string, so the length test comes first.
		if len(part) == 0 || len(part) > 3 || !isDigits(part) {
			return false
		}
		if len(part) > 1 && part[0] == '0' {
			return false
		}
		n := 0
		for i := 0; i < len(part); i++ {
			n = n*10 + int(part[i]-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}
