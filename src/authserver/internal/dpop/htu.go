package dpop

import (
	"strings"

	"github.com/leodip/goiabada/core/errs"
)

// normalizeHTTPURI returns an absolute http or https URI in the form RFC 3986's syntax-based
// (section 6.2.2) and scheme-based (section 6.2.3) normalization give it, its query and fragment
// dropped, as RFC 9449 section 4.3 compares htu: scheme and host in lower case, percent-encoding
// in upper case with every unreserved octet decoded, dot segments removed, a default or empty port
// dropped and an empty path read as /. A URI with userinfo, an empty host or a character no URI
// holds is refused, as is a relative reference.
func normalizeHTTPURI(raw string) (string, error) {
	if i := strings.IndexByte(raw, '#'); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		raw = raw[:i]
	}
	for i := 0; i < len(raw); i++ {
		if !isURIChar(raw[i]) {
			return "", errs.New("it holds a character no URI holds")
		}
	}

	schemeEnd := strings.Index(raw, "://")
	if schemeEnd < 0 {
		return "", errs.New("it is not an absolute URI with an authority")
	}
	scheme := strings.ToLower(raw[:schemeEnd])
	var defaultPort string
	switch scheme {
	case "https":
		defaultPort = "443"
	case "http":
		defaultPort = "80"
	default:
		return "", errs.New("its scheme is not http or https")
	}

	rest := raw[schemeEnd+len("://"):]
	authority, path := rest, ""
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		authority, path = rest[:i], rest[i:]
	}
	if strings.IndexByte(authority, '@') >= 0 {
		return "", errs.New("it has userinfo")
	}

	host, port := authority, ""
	if strings.HasPrefix(authority, "[") {
		end := strings.IndexByte(authority, ']')
		if end < 0 {
			return "", errs.New("its IP literal is not closed")
		}
		host, port = authority[:end+1], authority[end+1:]
		if port != "" && !strings.HasPrefix(port, ":") {
			return "", errs.New("its IP literal is followed by something other than a port")
		}
		port = strings.TrimPrefix(port, ":")
	} else if i := strings.LastIndexByte(authority, ':'); i >= 0 {
		host, port = authority[:i], authority[i+1:]
	}
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return "", errs.New("its port is not a number")
		}
	}
	if port == defaultPort {
		port = ""
	}

	host, err := normalizePercentEncoding(host)
	if err != nil {
		return "", err
	}
	host = lowerOutsideTriplets(host)
	if host == "" {
		return "", errs.New("its host is empty")
	}

	path, err = normalizePercentEncoding(path)
	if err != nil {
		return "", err
	}
	path = removeDotSegments(path)
	if path == "" {
		path = "/"
	}

	normalized := scheme + "://" + host
	if port != "" {
		normalized += ":" + port
	}
	return normalized + path, nil
}

// isURIChar reports whether c may appear in a URI: an unreserved or reserved character, or the %
// of a percent-encoding (RFC 3986 section 2).
func isURIChar(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("-._~:/?#[]@!$&'()*+,;=%", c) >= 0
}

func isUnreserved(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	}
	return c == '-' || c == '.' || c == '_' || c == '~'
}

func hexValue(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// normalizePercentEncoding decodes each percent-encoded unreserved octet and writes every other
// triplet's hex digits in upper case (RFC 3986 sections 6.2.2.1 and 6.2.2.2). A % not followed by
// two hex digits is refused.
func normalizePercentEncoding(s string) (string, error) {
	if strings.IndexByte(s, '%') < 0 {
		return s, nil
	}
	const upperHex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", errs.New("it has a truncated percent-encoding")
		}
		hi, ok1 := hexValue(s[i+1])
		lo, ok2 := hexValue(s[i+2])
		if !ok1 || !ok2 {
			return "", errs.New("it has a percent-encoding that is not two hex digits")
		}
		octet := hi<<4 | lo
		if isUnreserved(octet) {
			b.WriteByte(octet)
		} else {
			b.WriteByte('%')
			b.WriteByte(upperHex[hi])
			b.WriteByte(upperHex[lo])
		}
		i += 2
	}
	return b.String(), nil
}

// lowerOutsideTriplets lower-cases s except the hex digits of its percent-encodings, which stay in
// upper case.
func lowerOutsideTriplets(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] == '%' {
			i += 2
			continue
		}
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// removeDotSegments is RFC 3986 section 5.2.4's remove_dot_segments.
func removeDotSegments(input string) string {
	out := ""
	for input != "" {
		switch {
		case strings.HasPrefix(input, "../"):
			input = input[3:]
		case strings.HasPrefix(input, "./"):
			input = input[2:]
		case strings.HasPrefix(input, "/./"):
			input = input[2:]
		case input == "/.":
			input = "/"
		case strings.HasPrefix(input, "/../"):
			input = input[3:]
			out = dropLastSegment(out)
		case input == "/..":
			input = "/"
			out = dropLastSegment(out)
		case input == "." || input == "..":
			input = ""
		default:
			next := strings.IndexByte(input[1:], '/')
			if next < 0 {
				out += input
				input = ""
			} else {
				out += input[:next+1]
				input = input[next+1:]
			}
		}
	}
	return out
}

// dropLastSegment removes the last segment of out and the / before it, if any.
func dropLastSegment(out string) string {
	if i := strings.LastIndexByte(out, '/'); i >= 0 {
		return out[:i]
	}
	return ""
}
