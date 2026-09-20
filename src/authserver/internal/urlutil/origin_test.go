package urlutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCanonicalOrigin_ProbeTable is the ten rows of the issue's own measurement,
// probe/web_origin_normalization.out, run against the replacement rather than against the
// validator that produced them. Six of the ten were accepted verbatim and could never match
// the Origin header they were registered for; each of those six is here with the header the
// probe recorded the browser sending, so the table asserts the defect is closed rather than
// asserting whatever the new code happens to do (#250 W2).
func TestCanonicalOrigin_ProbeTable(t *testing.T) {
	tests := []struct {
		typed         string
		browserSends  string
		wasSilentlyOK bool // accepted by the old validator and permanently dead
	}{
		{"https://app.example.com", "https://app.example.com", false},
		{"https://app.example.com/", "https://app.example.com", true},
		{"https://app.example.com/callback", "https://app.example.com", true},
		{"https://APP.example.com", "https://app.example.com", false},
		{"https://app.example.com:443", "https://app.example.com", true},
		{"http://app.example.com:80", "http://app.example.com", true},
		{"http://localhost:3000", "http://localhost:3000", false},
		{"http://localhost:3000/", "http://localhost:3000", true},
		{"https://app.example.com?x=1", "https://app.example.com", true},
		{"https://app.example.com#frag", "https://app.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.typed, func(t *testing.T) {
			got, ok := CanonicalOrigin(tt.typed)
			assert.True(t, ok, "%q must be accepted: a browser serves it and sends %q", tt.typed, tt.browserSends)
			assert.Equal(t, tt.browserSends, got,
				"stored form must be the exact Origin header the browser sends, or CORS can never match it")
		})
	}
}

// TestCanonicalOrigin_Converts covers the whole of decision 14's conversion half: case, a
// trailing slash, a path, a query, a fragment, surrounding whitespace and a default port. Any
// row here that starts being refused instead narrows the endpoint against an administrator who
// pasted a URL out of a browser bar, which is the shape the issue is about.
func TestCanonicalOrigin_Converts(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		// already canonical, both schemes, with and without a port
		{"https://app.example.com", "https://app.example.com"},
		{"http://app.example.com", "http://app.example.com"},
		{"https://app.example.com:8443", "https://app.example.com:8443"},
		{"http://localhost:3000", "http://localhost:3000"},
		{"http://127.0.0.1:3000", "http://127.0.0.1:3000"},

		// case, on the scheme and on the host, together and apart
		{"HTTPS://app.example.com", "https://app.example.com"},
		{"https://APP.EXAMPLE.COM", "https://app.example.com"},
		{"HtTpS://ApP.ExAmPlE.cOm", "https://app.example.com"},

		// everything after the authority
		{"https://app.example.com/", "https://app.example.com"},
		{"https://app.example.com/callback", "https://app.example.com"},
		{"https://app.example.com/a/b/c", "https://app.example.com"},
		{"https://app.example.com?x=1", "https://app.example.com"},
		{"https://app.example.com#frag", "https://app.example.com"},
		{"https://app.example.com#", "https://app.example.com"},
		{"https://app.example.com/?x=1#frag", "https://app.example.com"},
		{"https://app.example.com:8443/callback?x=1#f", "https://app.example.com:8443"},

		// the default port, on the scheme it is default for, and the same number kept on
		// the scheme it is not default for
		{"https://app.example.com:443", "https://app.example.com"},
		{"http://app.example.com:80", "http://app.example.com"},
		{"https://app.example.com:80", "https://app.example.com:80"},
		{"http://app.example.com:443", "http://app.example.com:443"},
		{"HTTPS://APP.example.com:443/x", "https://app.example.com"},

		// surrounding C0-control-or-space, which the WHATWG URL parser strips before a
		// browser ever sees the value
		{"  https://app.example.com  ", "https://app.example.com"},
		{"\thttps://app.example.com\n", "https://app.example.com"},
		{"\r\nhttps://app.example.com/ \t", "https://app.example.com"},

		// hosts that are not domains in the ordinary sense but are serialized verbatim
		{"http://localhost", "http://localhost"},
		{"http://my_host:8080", "http://my_host:8080"},
		{"http://-leading-hyphen.example", "http://-leading-hyphen.example"},
		{"https://example.com.", "https://example.com."},
		{"http://127.0.0.1", "http://127.0.0.1"},
		{"http://0.0.0.0", "http://0.0.0.0"},
		{"http://255.255.255.255", "http://255.255.255.255"},
		{"http://8.8.8.8:53", "http://8.8.8.8:53"},

		// the near miss of the refusal table's "ends in an IPv4 number" family: a last label
		// that opens with 0x is a hexadecimal number only while every digit after it is one,
		// and is an ordinary domain served verbatim the moment a single digit is not
		{"http://example.0xzz", "http://example.0xzz"},
		{"http://example.0x1f2g", "http://example.0x1f2g"},

		// the port range's own boundaries
		{"http://app.example.com:1", "http://app.example.com:1"},
		{"http://app.example.com:0", "http://app.example.com:0"},
		{"http://app.example.com:65535", "http://app.example.com:65535"},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, ok := CanonicalOrigin(tt.raw)
			assert.True(t, ok, "%q must be accepted", tt.raw)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestCanonicalOrigin_Refuses covers decision 14's refusal half. Every row is a shape a
// browser either rejects outright or serializes as some OTHER string, and converting it here
// would create a row migration 000034 cannot reproduce in SQL, since SQL has no punycode, no
// IPv6 compression and no IPv4 expansion. A row moving from here to the table above is
// therefore not a loosening, it is goal 11 failing.
func TestCanonicalOrigin_Refuses(t *testing.T) {
	tests := []struct {
		raw  string
		why  string
		name string
	}{
		// decision 14's ten named shapes, one case each
		{"https://bücher.example", "a non-ASCII host becomes punycode, which SQL cannot do", "non-ascii host"},
		{"https://user@example.com", "userinfo never appears in an Origin header", "userinfo"},
		{"https://[2001:0db8:0000:0000:0000:0000:0000:0001]", "a browser compresses this to [2001:db8::1]", "ipv6 literal"},
		{"https://example.com:", "a browser drops an empty port, so it sends a different string", "empty port"},
		{"https://example.com:0443", "a leading zero is still 443 to a browser", "leading-zero port"},
		{"http://127.1", "a browser expands this to 127.0.0.1", "shorthand ipv4"},
		{"http://2130706433", "a browser expands this to 127.0.0.1", "integer ipv4"},
		{"http://0x7f000001", "a browser expands this to 127.0.0.1", "hex ipv4"},
		{"https://example.com:99999", "outside the port range the URL parser accepts", "out-of-range port"},
		{"https://[fe80::1%25eth0]", "a zone identifier is not part of an origin", "zone identifier"},

		// the scheme
		{"ftp://example.com", "only http and https carry web origins", "ftp scheme"},
		{"file://example.com", "same", "file scheme"},
		{"example.com", "no scheme at all", "bare host"},
		{"//example.com", "scheme-relative", "scheme relative"},
		{"", "empty", "empty"},
		{"   ", "whitespace only", "whitespace only"},
		{"https:/example.com", "one slash is a path, not an authority", "single slash"},

		// the authority
		{"https://", "no authority", "no authority"},
		{"https:///example.com", "an empty authority followed by a path", "empty authority"},
		{"https://?x=1", "same, with a query", "empty authority query"},
		{"https://@example.com", "empty userinfo is still userinfo", "empty userinfo"},
		{"https://user:pass@example.com", "userinfo with a password", "userinfo password"},

		// the port
		{"https://example.com:http", "a service name is not a port", "service name port"},
		{"https://example.com:80a", "not decimal", "non-numeric port"},
		{"https://example.com:-1", "not decimal", "negative port"},
		{"https://example.com:65536", "one past the top of the range", "port 65536"},
		{"https://example.com:080", "a leading zero, on the default port", "leading-zero default port"},
		{"https://example.com: 443", "a space inside the authority", "space in port"},
		{"https://example.com:443:443", "two ports", "double port"},

		// the host's code points
		{"https://exa mple.com", "a space is a forbidden domain code point", "space in host"},
		{"https://exa\tmple.com", "a browser removes interior tabs, changing the host", "tab in host"},
		{"https://exa\nmple.com", "same, for newlines", "newline in host"},
		{"https://example.com\\path", "a backslash is a path separator to a browser", "backslash"},
		{"https://exam%70le.com", "a percent-escape in a host is forbidden", "percent escape"},
		{"https://exam<ple.com", "forbidden domain code point", "angle bracket"},
		{"https://exam|ple.com", "forbidden domain code point", "pipe"},
		{"https://exam^ple.com", "forbidden domain code point", "caret"},
		{"https://[example.com", "an unclosed bracket", "unclosed bracket"},
		{"https://example.com]", "a stray bracket", "stray bracket"},

		// the host's labels
		{"https://.", "a bare dot", "bare dot"},
		{"https://..", "two dots", "two dots"},
		{"https://.example.com", "an empty leading label", "empty leading label"},
		{"https://example..com", "an empty interior label", "empty interior label"},
		{"https://example.com..", "two trailing dots", "two trailing dots"},

		// hosts that end in an IPv4 number without being a strict dotted quad. This is the
		// family string arithmetic gets wrong, so it gets the near misses too.
		{"http://010.0.0.1", "a leading zero is octal, so a browser sends 8.0.0.1", "octal ipv4"},
		{"http://127.0.0.01", "same, in the last part", "octal last part"},
		{"http://999.1.1.1", "out of range, so a browser rejects it", "out-of-range ipv4"},
		{"http://256.0.0.1", "one past the top of a part", "ipv4 part 256"},
		{"http://1.2.3.4.5", "five parts", "five-part ipv4"},
		{"http://1.2.3", "three parts, expanded by a browser", "three-part ipv4"},
		{"http://127.0.0.1.", "a browser drops the trailing dot once it parses as IPv4", "dotted quad trailing dot"},
		{"http://0x7f.0.0.1", "a hex part is expanded", "hex part"},
		{"http://example.0x1", "the last label is a number, so the whole host is parsed as IPv4", "hex last label"},
		{"http://example.1", "same, in decimal", "decimal last label"},
		{"http://0x", "an empty hexadecimal number is still a number", "bare 0x"},
		{"http://127.0.0.1:0x50", "a hex port", "hex port"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := CanonicalOrigin(tt.raw)
			assert.False(t, ok, "%q must be refused: %s", tt.raw, tt.why)
			assert.Empty(t, got, "a refusal returns no value")
		})
	}
}

// TestCanonicalOrigin_IsIdempotent is the property migration 000034 has to reproduce in SQL on
// four engines. Every value the write path stores is an output of this function, so if feeding
// an output back in ever moved it, a stored row would not be a fixed point and the repair
// could not be checked by comparing against this function's answer (#250 decision 14).
func TestCanonicalOrigin_IsIdempotent(t *testing.T) {
	inputs := []string{
		"https://app.example.com",
		"https://APP.example.com/callback?x=1#f",
		"http://app.example.com:80",
		"https://app.example.com:443",
		"https://app.example.com:8443/",
		"  http://localhost:3000/  ",
		"http://127.0.0.1",
		"https://example.com.",
		"http://my_host:8080",
		"http://app.example.com:0",
	}

	for _, raw := range inputs {
		t.Run(raw, func(t *testing.T) {
			once, ok := CanonicalOrigin(raw)
			assert.True(t, ok)
			twice, ok := CanonicalOrigin(once)
			assert.True(t, ok, "a canonical origin must still be accepted")
			assert.Equal(t, once, twice, "canonicalizing a canonical origin must not move it")
		})
	}
}
