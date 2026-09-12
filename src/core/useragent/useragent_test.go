package useragent

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
)

// Labels owns the whole derivation, so this file owns the whole table. The three labels are
// display only -- StartNewUserSession keys its "same device" sweep on the raw header and the
// IP address (#281) -- but they are what a person reads when deciding which of their sessions
// to end, so every row of both paths is pinned here rather than at a consumer.
//
// The rows are the ones docs/issue-281-replace-useragent/probe/labels.go executes, which is
// where the derivation was settled before any of it was written into the tree.

const (
	chromeWindows = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	edgeWindows  = chromeWindows + " Edg/120.0.2210.91"
	firefoxLinux = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
	safariIPhone = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 " +
		"(KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1"
	safariIPad = "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 " +
		"(KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1"
	safariIPadDesktopMode = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 " +
		"(KHTML, like Gecko) Version/17.1 Safari/605.1.15"
	chromeAndroidPhone = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
	chromeAndroidTablet = "Mozilla/5.0 (Linux; Android 13; SM-X700) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	chromeIOS = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 " +
		"(KHTML, like Gecko) CriOS/120.0.6099.119 Mobile/15E148 Safari/604.1"
	chromeChromeOS = "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	googlebot = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	curlAgent = "curl/8.5.0"
)

// newRequest builds a request carrying exactly the headers a row names and nothing else, so a
// row meaning "this header is absent" simply omits it. httptest.NewRequest sends no
// User-Agent of its own, which is what makes the absent-header rows below reachable.
func newRequest(headers map[string]string) *http.Request {
	req := httptest.NewRequest("GET", "/", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

// The Client Hints path. Chromium sends Sec-CH-UA, Sec-CH-UA-Mobile and Sec-CH-UA-Platform by
// default because all three are in the low-entropy table, and it sends them only in a secure
// context; no other engine sends any of them. UA-CH 8.2 requires an arbitrary GREASE brand
// among the list and requires the order to change over time, so no row may depend on a brand
// sitting in a known position.
func TestLabels_ClientHints(t *testing.T) {
	testCases := []struct {
		name                       string
		headers                    map[string]string
		wantName, wantType, wantOS string
	}{
		{
			name: "chrome on windows, GREASE last",
			headers: map[string]string{
				"Sec-CH-UA":          `"Chromium";v="120", "Google Chrome";v="120", "Not?A_Brand";v="24"`,
				"Sec-CH-UA-Mobile":   "?0",
				"Sec-CH-UA-Platform": `"Windows"`,
				"User-Agent":         chromeWindows,
			},
			wantName: "Chrome 120", wantType: "Desktop", wantOS: "Windows",
		},
		{
			// The same browser with the list in another order and no User-Agent at all. Same
			// answer: the brand is chosen by what it is, never by where it sits.
			name: "chrome on windows, GREASE first",
			headers: map[string]string{
				"Sec-CH-UA":          `"Not A Brand";v="99", "Chromium";v="120", "Google Chrome";v="120"`,
				"Sec-CH-UA-Mobile":   "?0",
				"Sec-CH-UA-Platform": `"Windows"`,
			},
			wantName: "Chrome 120", wantType: "Desktop", wantOS: "Windows",
		},
		{
			name: "edge on macOS, read as Edge rather than Microsoft Edge",
			headers: map[string]string{
				"Sec-CH-UA":          `"Not_A Brand";v="8", "Chromium";v="120", "Microsoft Edge";v="120"`,
				"Sec-CH-UA-Mobile":   "?0",
				"Sec-CH-UA-Platform": `"macOS"`,
			},
			wantName: "Edge 120", wantType: "Desktop", wantOS: "macOS",
		},
		{
			// A fork the ordered User-Agent list does not know, named correctly here because
			// the hints carry the brand rather than a string pretending to be Chrome.
			name: "brave on linux",
			headers: map[string]string{
				"Sec-CH-UA":          `"Brave";v="120", "Chromium";v="120", "Not:A-Brand";v="99"`,
				"Sec-CH-UA-Mobile":   "?0",
				"Sec-CH-UA-Platform": `"Linux"`,
			},
			wantName: "Brave 120", wantType: "Desktop", wantOS: "Linux",
		},
		{
			name: "opera on an android phone",
			headers: map[string]string{
				"Sec-CH-UA":          `"Opera";v="106", "Chromium";v="120", "Not(A:Brand";v="8"`,
				"Sec-CH-UA-Mobile":   "?1",
				"Sec-CH-UA-Platform": `"Android"`,
			},
			wantName: "Opera 106", wantType: "Mobile", wantOS: "Android",
		},
		{
			name: "chromium alone, which is headless chrome and electron",
			headers: map[string]string{
				"Sec-CH-UA":          `"Chromium";v="120", "Not/A)Brand";v="24"`,
				"Sec-CH-UA-Mobile":   "?0",
				"Sec-CH-UA-Platform": `"Linux"`,
			},
			wantName: "Chromium 120", wantType: "Desktop", wantOS: "Linux",
		},
		{
			// Keep this: the expected value looks wrong and is not. When every brand looks
			// like GREASE the first one as sent is used, because a session labelled from
			// nothing is worse than one labelled oddly.
			name: "every brand looks like GREASE",
			headers: map[string]string{
				"Sec-CH-UA":          `"Not/A)Brand";v="24"`,
				"Sec-CH-UA-Mobile":   "?0",
				"Sec-CH-UA-Platform": `"Linux"`,
			},
			wantName: "Not/A)Brand 24", wantType: "Desktop", wantOS: "Linux",
		},
		{
			// The positive control for the escape gate: \" is one of the two escapes RFC 9651
			// 3.3.3 allows, so this list parses and the quote survives into the name. v carries
			// a full version and only the major is displayed (decision 3), and the platform
			// "Unknown" is one UA-CH 3.9 lists and means absent.
			name: "an escaped quote in a brand, a full version in v, an Unknown platform",
			headers: map[string]string{
				"Sec-CH-UA":          `"We\"ird";v="1.2.3"`,
				"Sec-CH-UA-Mobile":   "?1",
				"Sec-CH-UA-Platform": `"Unknown"`,
			},
			wantName: `We"ird 1`, wantType: "Mobile", wantOS: "",
		},
		{
			name: "an escaped quote in the platform survives too",
			headers: map[string]string{
				"Sec-CH-UA":          `"Google Chrome";v="120"`,
				"Sec-CH-UA-Platform": `"Win\"dows"`,
				"User-Agent":         chromeWindows,
			},
			wantName: "Chrome 120", wantType: "Desktop", wantOS: `Win"dows`,
		},
		{
			// Sec-CH-UA alone is enough to take this path. Both other hints absent: the type
			// falls to Desktop and the platform to empty rather than to the User-Agent's.
			name: "the mobile and platform hints are both absent",
			headers: map[string]string{
				"Sec-CH-UA": `"Google Chrome";v="120", "Chromium";v="120", "Not?A_Brand";v="24"`,
			},
			wantName: "Chrome 120", wantType: "Desktop", wantOS: "",
		},
		{
			// Gate: UA-CH 3.7 makes Sec-CH-UA-Mobile a boolean, so "?1" is the only value that
			// means mobile. A reader treating any non-empty value as true labels this Mobile.
			name: "a mobile hint that is not a boolean is not mobile",
			headers: map[string]string{
				"Sec-CH-UA":          `"Google Chrome";v="120"`,
				"Sec-CH-UA-Mobile":   "yes",
				"Sec-CH-UA-Platform": `"Windows"`,
			},
			wantName: "Chrome 120", wantType: "Desktop", wantOS: "Windows",
		},
		// The five rows below carry a valid parameter on a key nothing reads, paired with a
		// Firefox User-Agent so the answer says which path ran. Each is a bare-item form that
		// a reader of the obsolete RFC 8941 set refuses, and refusing means falling through to
		// a User-Agent Chromium freezes -- reporting Firefox on Linux for a Chrome on Windows,
		// which is the whole failure decision 2 of #281 exists to avoid.
		{
			// RFC 9651 4.2.3.1 step 6: "@" starts a Date (3.3.7), which 8941 did not have.
			name: "a date parameter, an RFC 9651 form RFC 8941 lacked",
			headers: map[string]string{
				"Sec-CH-UA":          `"Google Chrome";v="120";seen=@1659578233`,
				"Sec-CH-UA-Platform": `"Windows"`,
				"User-Agent":         firefoxLinux,
			},
			wantName: "Chrome 120", wantType: "Desktop", wantOS: "Windows",
		},
		{
			// RFC 9651 4.2.3.1 step 7: "%" starts a Display String (3.3.8). Its body carries
			// lowercase pct-encoding, and "\" stands for itself rather than escaping, which is
			// where 4.2.10 parts company with the sf-string reader beside it.
			name: "a display string parameter, an RFC 9651 form RFC 8941 lacked",
			headers: map[string]string{
				"Sec-CH-UA":          `"Google Chrome";v="120";note=%"caf%c3%a9 a\b"`,
				"Sec-CH-UA-Platform": `"Windows"`,
				"User-Agent":         firefoxLinux,
			},
			wantName: "Chrome 120", wantType: "Desktop", wantOS: "Windows",
		},
		{
			// The positive control for the base64 decode gate: a byte sequence that does
			// decode still parses, so the gate refuses malformed content rather than the form.
			name: "a byte sequence parameter that decodes",
			headers: map[string]string{
				"Sec-CH-UA":          `"Google Chrome";v="120";other=:QQ==:`,
				"Sec-CH-UA-Platform": `"Windows"`,
				"User-Agent":         firefoxLinux,
			},
			wantName: "Chrome 120", wantType: "Desktop", wantOS: "Windows",
		},
		{
			// And the same byte with its padding omitted, which RFC 9651 4.2.7 step 7 says to
			// synthesize rather than refuse. A decoder demanding padding rejects this.
			name: "a byte sequence parameter with its padding omitted",
			headers: map[string]string{
				"Sec-CH-UA":          `"Google Chrome";v="120";other=:QQ:`,
				"Sec-CH-UA-Platform": `"Windows"`,
				"User-Agent":         firefoxLinux,
			},
			wantName: "Chrome 120", wantType: "Desktop", wantOS: "Windows",
		},
		{
			// An empty byte sequence is the empty string base64-decoded, which succeeds.
			name: "an empty byte sequence parameter",
			headers: map[string]string{
				"Sec-CH-UA":          `"Google Chrome";v="120";other=::`,
				"Sec-CH-UA-Platform": `"Windows"`,
				"User-Agent":         firefoxLinux,
			},
			wantName: "Chrome 120", wantType: "Desktop", wantOS: "Windows",
		},
		// The rows below put those same bare-item forms on v itself, where UA-CH 4.1.4 has
		// already decided the answer: it sets param_value to version, "a string", and
		// NavigatorUABrandVersion declares version a DOMString. A v of any other type is
		// therefore a parameter this package cannot use, not a version spelled unusually, and
		// the brand is displayed without one. Each row still expects the hints path to have
		// run -- the field parses, only its v is unusable -- which the Firefox User-Agent
		// beside it is there to prove: "Chrome" means the hints were read, "Firefox 121" would
		// mean the whole header was refused.
		{
			name: "a v parameter that is a date is not a version",
			headers: map[string]string{
				"Sec-CH-UA":          `"Google Chrome";v=@1659578233`,
				"Sec-CH-UA-Platform": `"Windows"`,
				"User-Agent":         firefoxLinux,
			},
			wantName: "Chrome", wantType: "Desktop", wantOS: "Windows",
		},
		{
			// The display string is the form that made this worth fixing rather than tidying:
			// its source span carries pct-encoding, so "12%2e3" holds no literal "." to cut at
			// and the whole of %"12%2e3" would have been displayed as the major version.
			name: "a v parameter that is a display string is not a version",
			headers: map[string]string{
				"Sec-CH-UA":          `"Google Chrome";v=%"12%2e3"`,
				"Sec-CH-UA-Platform": `"Windows"`,
				"User-Agent":         firefoxLinux,
			},
			wantName: "Chrome", wantType: "Desktop", wantOS: "Windows",
		},
		{
			name: "a v parameter that is a boolean is not a version",
			headers: map[string]string{
				"Sec-CH-UA":          `"Google Chrome";v=?1`,
				"Sec-CH-UA-Platform": `"Windows"`,
				"User-Agent":         firefoxLinux,
			},
			wantName: "Chrome", wantType: "Desktop", wantOS: "Windows",
		},
		{
			name: "a v parameter that is a byte sequence is not a version",
			headers: map[string]string{
				"Sec-CH-UA":          `"Google Chrome";v=:MTI=:`,
				"Sec-CH-UA-Platform": `"Windows"`,
				"User-Agent":         firefoxLinux,
			},
			wantName: "Chrome", wantType: "Desktop", wantOS: "Windows",
		},
		{
			// A valueless parameter is boolean true (RFC 9651 3.1.2), which is the one non-
			// string form that read as "no version" before this rule existed, by accident: the
			// empty value it answered cut to the empty string.
			name: "a valueless v parameter is not a version",
			headers: map[string]string{
				"Sec-CH-UA":          `"Google Chrome";v`,
				"Sec-CH-UA-Platform": `"Windows"`,
				"User-Agent":         firefoxLinux,
			},
			wantName: "Chrome", wantType: "Desktop", wantOS: "Windows",
		},
		{
			name: "a v parameter that is a token is not a version",
			headers: map[string]string{
				"Sec-CH-UA":          `"Google Chrome";v=v120`,
				"Sec-CH-UA-Platform": `"Windows"`,
				"User-Agent":         firefoxLinux,
			},
			wantName: "Chrome", wantType: "Desktop", wantOS: "Windows",
		},
		{
			// An integer is the form most likely to be sent by something hand-rolling the
			// header, and it is still not a String, so it is still not a version.
			name: "a v parameter that is an integer is not a version",
			headers: map[string]string{
				"Sec-CH-UA":          `"Google Chrome";v=120`,
				"Sec-CH-UA-Platform": `"Windows"`,
				"User-Agent":         firefoxLinux,
			},
			wantName: "Chrome", wantType: "Desktop", wantOS: "Windows",
		},
		{
			// Parameters are a dictionary (RFC 9651 3.1.2), so a repeated key is the later
			// value and not the first one. A reader that only assigned on a string would keep
			// "120" here, which is the earlier v.
			name: "a repeated v whose later value is not a string leaves no version",
			headers: map[string]string{
				"Sec-CH-UA":          `"Google Chrome";v="120";v=?1`,
				"Sec-CH-UA-Platform": `"Windows"`,
				"User-Agent":         firefoxLinux,
			},
			wantName: "Chrome", wantType: "Desktop", wantOS: "Windows",
		},
		{
			// And the same dictionary rule the other way: the later string wins over the
			// earlier unusable value.
			name: "a repeated v whose later value is a string is the version",
			headers: map[string]string{
				"Sec-CH-UA":          `"Google Chrome";v=?1;v="120"`,
				"Sec-CH-UA-Platform": `"Windows"`,
				"User-Agent":         firefoxLinux,
			},
			wantName: "Chrome 120", wantType: "Desktop", wantOS: "Windows",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			name, deviceType, os := Labels(newRequest(tc.headers))

			assert.Equal(t, tc.wantName, name)
			assert.Equal(t, tc.wantType, deviceType)
			assert.Equal(t, tc.wantOS, os)
		})
	}
}

// Every way the Sec-CH-UA reader refuses, and what each refusal costs. RFC 8942 2.2 says a
// server "MUST ignore hints they do not understand nor support", so a refusal is a fall
// through to the User-Agent rather than an error or a half-read label.
//
// Each brand-list row pairs a Chrome-shaped hint header with a Firefox User-Agent, so the
// expected labels can only have come from the fallback: a reader that accepted the header
// would answer "Chrome 120", and a reader that accepted it half-read would answer something
// odder still. Each row names the gate meant to reject it.
func TestLabels_ClientHintsThatDoNotParseFallToTheUserAgent(t *testing.T) {
	testCases := []struct {
		name                       string
		headers                    map[string]string
		wantName, wantType, wantOS string
	}{
		{
			// Gate: an sf-list member is an sf-string, which begins with a quote.
			name: "not a structured field at all",
			headers: map[string]string{
				"Sec-CH-UA":  `not a structured field`,
				"User-Agent": firefoxLinux,
			},
			wantName: "Firefox 121", wantType: "Desktop", wantOS: "Linux",
		},
		{
			// Gate: RFC 9651 3.3.3, "other characters after '\' MUST cause parsing to fail".
			// Without it the brand reads Chro\me and is stored as a browser name.
			name: "an escape of anything but a quote or a backslash",
			headers: map[string]string{
				"Sec-CH-UA":  `"Chro\me";v="120"`,
				"User-Agent": firefoxLinux,
			},
			wantName: "Firefox 121", wantType: "Desktop", wantOS: "Linux",
		},
		{
			// Gate: a member is its string, then its parameters, then a comma or the end of
			// the field (RFC 9651 3.1). Pinning it takes a contrived header, and the shape is
			// the point: a reader without the gate steps over one character and carries on,
			// so it resynchronises onto the next quote and reads a list the sender never
			// sent. Ordinary malformations do not show that -- junk that is not a member
			// start, and a missing comma, are both refused by parseString at the next member
			// whether the gate is there or not -- so this row puts exactly one junk character
			// where the comma belongs. With the gate deleted it answers Chrome 120.
			name: "a member separated from the next by one junk character",
			headers: map[string]string{
				"Sec-CH-UA":  `"Chromium";v="120" x"Google Chrome";v="120"`,
				"User-Agent": firefoxLinux,
			},
			wantName: "Firefox 121", wantType: "Desktop", wantOS: "Linux",
		},
		{
			// Rejected by parseString rather than by the comma gate: after the comma there is
			// no member, and RFC 9651 3.1 has no empty one.
			name: "a trailing comma",
			headers: map[string]string{
				"Sec-CH-UA":  `"Google Chrome";v="120",`,
				"User-Agent": firefoxLinux,
			},
			wantName: "Firefox 121", wantType: "Desktop", wantOS: "Linux",
		},
		{
			// Same mechanism, one step later: whatever trails a member, the next member is
			// where the list stops.
			name: "junk between a member and the comma after it",
			headers: map[string]string{
				"Sec-CH-UA":  `"Chromium";v="120" x, "Google Chrome";v="120"`,
				"User-Agent": firefoxLinux,
			},
			wantName: "Firefox 121", wantType: "Desktop", wantOS: "Linux",
		},
		{
			// Gate: RFC 9651 3.3.3 unescaped = %x20-21 / %x23-5B / %x5D-7E, so a control
			// character is not a character an sf-string may carry unescaped.
			name: "a control character inside a brand",
			headers: map[string]string{
				"Sec-CH-UA":  "\"Chro\x01me\";v=\"120\"",
				"User-Agent": firefoxLinux,
			},
			wantName: "Firefox 121", wantType: "Desktop", wantOS: "Linux",
		},
		{
			// Gate: an unterminated string reaches the end of the field without a closing
			// quote, which is the third way parseString refuses.
			name: "a brand whose string never closes",
			headers: map[string]string{
				"Sec-CH-UA":  `"Google Chrome";v="120", "Chromiu`,
				"User-Agent": firefoxLinux,
			},
			wantName: "Firefox 121", wantType: "Desktop", wantOS: "Linux",
		},
		{
			// Gate: an empty Sec-CH-UA is an empty list, which UA-CH never sends and RFC 9651
			// 3.1 does not admit as a member.
			name: "an empty Sec-CH-UA",
			headers: map[string]string{
				"Sec-CH-UA":  "",
				"User-Agent": firefoxLinux,
			},
			wantName: "Firefox 121", wantType: "Desktop", wantOS: "Linux",
		},
		{
			// Gate: RFC 9651 3.1.2 param-key = key = ( lcalpha / "*" ) *( lcalpha / DIGIT /
			// "_" / "-" / "." / "*" ). Uppercase is not in it, so "V" is not the v parameter
			// spelled differently -- it is a header that is not a structured field. A reader
			// on the wider HTTP token grammar takes the key, fails to match "v", and labels
			// the session "Google Chrome" with no version at all.
			name: "a parameter key outside RFC 9651's key grammar",
			headers: map[string]string{
				"Sec-CH-UA":  `"Google Chrome";V="120"`,
				"User-Agent": firefoxLinux,
			},
			wantName: "Firefox 121", wantType: "Desktop", wantOS: "Linux",
		},
		{
			// Gate: the same key production, read for where it *starts*. The two rows around
			// this one prove the gate is there; this one proves it is the grammar's and not a
			// looser set, and it is the only row that can. A key reader widened to HTTP tokens
			// refuses "V" anyway, because "V" is not a continuation character either, so the
			// cursor never moves and the comma gate below refuses the member; and it refuses
			// "=" anyway, because "=" is in neither set. A digit is the case where the two
			// disagree and the parse still runs on: it starts no key in RFC 9651 but continues
			// one, so a widened reader takes "1x" as a key, reads its value, finishes the list
			// cleanly and labels the session Chrome 120. The same holds for "-", "." and "_",
			// which fail the same predicate and pass the same continuation.
			name: "a parameter key starting with a digit",
			headers: map[string]string{
				"Sec-CH-UA":  `"Google Chrome";v="120";1x=2`,
				"User-Agent": firefoxLinux,
			},
			wantName: "Firefox 121", wantType: "Desktop", wantOS: "Linux",
		},
		{
			// Gate: a parameter has a key, and RFC 9651 3.1.2's key production has no empty
			// form. This is the row that reaches that gate rather than the comma gate after
			// it: the uppercase row above is refused either way, because a key reader that
			// takes nothing leaves the cursor on a byte that is not a comma, whereas here the
			// bare item consumes the rest of the field and the list ends cleanly. So without
			// the gate this one parses, and a header with a nameless parameter is honoured.
			name: "a parameter with no key at all",
			headers: map[string]string{
				"Sec-CH-UA":  `"Google Chrome";v="120";=1`,
				"User-Agent": firefoxLinux,
			},
			wantName: "Firefox 121", wantType: "Desktop", wantOS: "Linux",
		},
		{
			// Gate: param-value = bare-item (RFC 9651 3.1.2). "@" starts a Date, and 4.2.9
			// reads what follows as an sf-integer, which "junk" is not. Without the gate the
			// version reads "@junk" and "Google Chrome @junk" goes into device_name.
			name: "a parameter value that is not a bare item",
			headers: map[string]string{
				"Sec-CH-UA":  `"Google Chrome";v=@junk`,
				"User-Agent": firefoxLinux,
			},
			wantName: "Firefox 121", wantType: "Desktop", wantOS: "Linux",
		},
		{
			// Same gate at its emptiest: "=" promises a bare item and there is none. A reader
			// that scanned to the next delimiter instead accepts this as the version "".
			name: "a parameter with an equals sign and no value",
			headers: map[string]string{
				"Sec-CH-UA":  `"Google Chrome";v=`,
				"User-Agent": firefoxLinux,
			},
			wantName: "Firefox 121", wantType: "Desktop", wantOS: "Linux",
		},
		{
			// A malformed parameter refuses the whole header even when it is not the one this
			// package reads: the field either is a structured field or it is not, and half of
			// one is what RFC 8942 2.2 says to ignore.
			name: "a malformed parameter on a key nothing reads",
			headers: map[string]string{
				"Sec-CH-UA":  `"Google Chrome";v="120";bad=@oops`,
				"User-Agent": firefoxLinux,
			},
			wantName: "Firefox 121", wantType: "Desktop", wantOS: "Linux",
		},
		{
			// Gate: sf-integer is at most 15 digits (RFC 9651 3.3.1), so sixteen is not a
			// bare item.
			name: "an integer parameter longer than sf-integer allows",
			headers: map[string]string{
				"Sec-CH-UA":  `"Google Chrome";v=1234567890123456`,
				"User-Agent": firefoxLinux,
			},
			wantName: "Firefox 121", wantType: "Desktop", wantOS: "Linux",
		},
		{
			// Gate: sf-decimal takes one to three digits after the point (RFC 9651 3.3.2).
			name: "a decimal parameter with four fractional digits",
			headers: map[string]string{
				"Sec-CH-UA":  `"Google Chrome";v=1.2345`,
				"User-Agent": firefoxLinux,
			},
			wantName: "Firefox 121", wantType: "Desktop", wantOS: "Linux",
		},
		{
			// Gate: RFC 9651 3.1.2 separates a parameter from its ";" with *SP, not OWS.
			name: "a tab between the semicolon and the parameter",
			headers: map[string]string{
				"Sec-CH-UA":  "\"Google Chrome\";\tv=\"120\"",
				"User-Agent": firefoxLinux,
			},
			wantName: "Firefox 121", wantType: "Desktop", wantOS: "Linux",
		},
		{
			// Gate: an unterminated byte sequence must not swallow the rest of the field
			// (RFC 9651 3.3.5).
			name: "a byte sequence that never closes",
			headers: map[string]string{
				"Sec-CH-UA":  `"Google Chrome";v=:AAAA`,
				"User-Agent": firefoxLinux,
			},
			wantName: "Firefox 121", wantType: "Desktop", wantOS: "Linux",
		},
		{
			// Gate: RFC 9651 4.2.7 step 6 checks the alphabet and step 7 then decodes,
			// "if base64 decoding fails, parsing fails". One base64 character is six bits,
			// which is no whole byte, so it passes the alphabet check and fails the decode.
			// With only the alphabet check the whole malformed hint is used.
			name: "a byte sequence whose content cannot be base64-decoded",
			headers: map[string]string{
				"Sec-CH-UA":  `"Google Chrome";v="120";other=:A:`,
				"User-Agent": firefoxLinux,
			},
			wantName: "Firefox 121", wantType: "Desktop", wantOS: "Linux",
		},
		{
			// Same gate, the other way a run of alphabet characters fails to decode: padding
			// is only ever trailing, so "=" before content is not a synthesizable omission.
			name: "a byte sequence with padding where content belongs",
			headers: map[string]string{
				"Sec-CH-UA":  `"Google Chrome";v="120";other=:=A==:`,
				"User-Agent": firefoxLinux,
			},
			wantName: "Firefox 121", wantType: "Desktop", wantOS: "Linux",
		},
		{
			// Gate: RFC 9651 4.2 step 2 discards leading SP before the list parser runs, and
			// OWS only between members (4.2.1). Not reachable over HTTP/1, where Go strips
			// field-line edge whitespace before the handler sees the request, so this pins the
			// grammar at the one seam that can still be handed a tab: another caller in this
			// process building a request by hand.
			name: "a tab before the first list member",
			headers: map[string]string{
				"Sec-CH-UA":  "\t" + `"Google Chrome";v="120"`,
				"User-Agent": firefoxLinux,
			},
			wantName: "Firefox 121", wantType: "Desktop", wantOS: "Linux",
		},
		{
			// Gate: sf-date is "@" sf-integer (RFC 9651 3.3.7), and 4.2.9 step 4 fails parsing
			// when what follows is a Decimal. The point is the whole of the difference.
			name: "a date parameter that is a decimal",
			headers: map[string]string{
				"Sec-CH-UA":  `"Google Chrome";v="120";seen=@1659578233.5`,
				"User-Agent": firefoxLinux,
			},
			wantName: "Firefox 121", wantType: "Desktop", wantOS: "Linux",
		},
		{
			// Gate: RFC 9651 3.3.8 pct-encoded takes lc-hexdig, DIGIT / %x61-66. Upper case is
			// not the same octet spelled differently, it is a field that does not parse.
			name: "a display string with upper-case percent-encoding",
			headers: map[string]string{
				"Sec-CH-UA":  `"Google Chrome";v="120";note=%"caf%C3%A9"`,
				"User-Agent": firefoxLinux,
			},
			wantName: "Firefox 121", wantType: "Desktop", wantOS: "Linux",
		},
		{
			// Gate: RFC 9651 4.2.10's closing step decodes byte_array as UTF-8 and fails
			// parsing if that fails. %ff alone is no UTF-8 sequence.
			name: "a display string whose octets are not valid UTF-8",
			headers: map[string]string{
				"Sec-CH-UA":  `"Google Chrome";v="120";note=%"%ff"`,
				"User-Agent": firefoxLinux,
			},
			wantName: "Firefox 121", wantType: "Desktop", wantOS: "Linux",
		},
		{
			// Gate: 4.2.10 rejects anything outside VCHAR and SP in the encoded text, so a
			// display string carrying a raw control character is not one.
			name: "a display string carrying a raw control character",
			headers: map[string]string{
				"Sec-CH-UA":  "\"Google Chrome\";v=\"120\";note=%\"a\x01b\"",
				"User-Agent": firefoxLinux,
			},
			wantName: "Firefox 121", wantType: "Desktop", wantOS: "Linux",
		},
		{
			// Gate: a display string is "%" DQUOTE, never "%" alone. Without the quote check
			// the "%" branch is entered and the rest of the field is read as its body.
			name: "a percent that opens no display string",
			headers: map[string]string{
				"Sec-CH-UA":  `"Google Chrome";v="120";note=%junk`,
				"User-Agent": firefoxLinux,
			},
			wantName: "Firefox 121", wantType: "Desktop", wantOS: "Linux",
		},
		{
			// Gate: unterminated, the display string's version of the row above it.
			name: "a display string that never closes",
			headers: map[string]string{
				"Sec-CH-UA":  `"Google Chrome";v="120";note=%"hello`,
				"User-Agent": firefoxLinux,
			},
			wantName: "Firefox 121", wantType: "Desktop", wantOS: "Linux",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			name, deviceType, os := Labels(newRequest(tc.headers))

			assert.Equal(t, tc.wantName, name)
			assert.Equal(t, tc.wantType, deviceType)
			assert.Equal(t, tc.wantOS, os)
		})
	}
}

// Sec-CH-UA-Platform goes through the same sf-string reader, so it is absent unless it parses
// as one whole sf-string. The brands parse in every row here, which is what makes the platform
// the only label that moves and keeps each row a test of one thing.
func TestLabels_PlatformHintsThatDoNotParseAreAbsent(t *testing.T) {
	testCases := []struct {
		name     string
		platform string
	}{
		// Gate: an sf-string is quoted. Without the gate this reads as the platform Windows,
		// which is the shape the derivation had before the gates were added.
		{"unquoted", "Windows"},
		// Gate: RFC 9651 3.3.3 again, the escape rule, on the platform rather than a brand.
		{"an invalid escape", `"Win\dows"`},
		// Gate: nothing may trail the closing quote.
		{"junk after the closing quote", `"Windows" x`},
		// Gate: unterminated.
		{"never closed", `"Windows`},
		// Gate: a control character, unescaped.
		{"a control character", "\"Win\x01dows\""},
		// Gate: RFC 9651 4.2 steps 2 and 6 bracket a field with *SP, not OWS, and an Item has
		// no parser of its own that discards OWS the way a list does around its commas. Both
		// edges, because they are separate sites in the code and a fix to one is not a fix to
		// the other. Neither is reachable over HTTP/1 -- Go strips field-line edge whitespace
		// before the handler runs -- so these pin the grammar rather than a wire case.
		{"a leading tab", "\t" + `"Windows"`},
		{"a trailing tab", `"Windows"` + "\t"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			name, deviceType, os := Labels(newRequest(map[string]string{
				"Sec-CH-UA":          `"Google Chrome";v="120"`,
				"Sec-CH-UA-Platform": tc.platform,
				"User-Agent":         chromeWindows,
			}))

			// The brands still parsed, so the other two labels are the hints path's and the
			// User-Agent's Windows is not consulted for the OS.
			assert.Equal(t, "Chrome 120", name)
			assert.Equal(t, "Desktop", deviceType)
			assert.Equal(t, "", os)
		})
	}
}

// A header may arrive as more than one field line, and a structured field's value is those
// lines joined with ", " before anything parses them (RFC 9110 5.3, RFC 9651 4.2).
//
// http.Header.Get answers the first line alone, which is wrong in both directions at once: a
// Sec-CH-UA legitimately split after its GREASE brand reads as a one-brand list and the session
// is labelled from the arbitrary value UA-CH 8.2 requires be there, while two Sec-CH-UA-Platform
// lines read as the first rather than as the invalid Item they combine into. These rows use
// Header.Add, which is what a repeated field line is on the server side.
func TestLabels_RepeatedFieldLinesAreJoinedBeforeParsing(t *testing.T) {
	t.Run("a brand list split across two field lines", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Add("Sec-CH-UA", `"Not A;Brand";v="99"`)
		req.Header.Add("Sec-CH-UA", `"Chromium";v="120", "Google Chrome";v="120"`)
		req.Header.Set("Sec-CH-UA-Platform", `"Windows"`)

		// Reading the first line alone leaves GREASE as the only brand, and pickBrand's last
		// resort hands back the first brand as sent rather than labelling from nothing.
		name, deviceType, os := Labels(req)
		assert.Equal(t, "Chrome 120", name)
		assert.Equal(t, "Desktop", deviceType)
		assert.Equal(t, "Windows", os)
	})

	// An Item-valued hint has no list to join into, so two lines combine into something that
	// is not an Item at all. RFC 8942 2.2 makes that a hint to ignore, which is exactly what
	// each field's own gate does once the lines are joined: the mobile flag is compared
	// against "?1" and the platform goes through the sf-string reader whole.
	t.Run("a repeated mobile hint is not a boolean", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Sec-CH-UA", `"Google Chrome";v="120"`)
		req.Header.Add("Sec-CH-UA-Mobile", "?1")
		req.Header.Add("Sec-CH-UA-Mobile", "?0")

		_, deviceType, _ := Labels(req)
		assert.Equal(t, "Desktop", deviceType)
	})

	t.Run("a repeated platform hint is not one sf-string", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Sec-CH-UA", `"Google Chrome";v="120"`)
		req.Header.Add("Sec-CH-UA-Platform", `"Windows"`)
		req.Header.Add("Sec-CH-UA-Platform", `"Linux"`)

		_, _, os := Labels(req)
		assert.Equal(t, "", os)
	})
}

// A brand and a platform are arbitrary text, by specification: UA-CH 3 says a server "MUST
// accept arbitrary values for each" of these properties, and an RFC 9651 sf-string admits every
// printable ASCII character, angle brackets and quotes among them. So markup in a label is not
// a header to reject -- rejecting it would be the source-side filtering UA-CH forbids -- it is
// a value every consumer has to render as text.
//
// This row is the premise of that obligation, and it is pinned here so the two places that
// discharge it cannot drift from it: the Device cell and its tooltip, escaped by html/template,
// and the End Session modal message, escaped by escapeHtml at the concatenation because
// showModalDialog assigns that message to innerHTML. Both are proved in the admin console's
// rendertest package, over the real templates (#281).
func TestLabels_HintsCarryArbitraryTextIncludingMarkup(t *testing.T) {
	const markup = `<script>alert(1)</script>`

	name, deviceType, os := Labels(newRequest(map[string]string{
		"Sec-CH-UA":          `"` + markup + `";v="1"`,
		"Sec-CH-UA-Platform": `"` + markup + `"`,
		"User-Agent":         chromeWindows,
	}))

	assert.Equal(t, markup+" 1", name)
	assert.Equal(t, "Desktop", deviceType)
	assert.Equal(t, markup, os)
}

// The User-Agent path: the only path for Firefox, Safari, a plain-HTTP deployment and every
// non-browser client, so it carries the same weight as the hints path rather than less.
func TestLabels_UserAgentFallback(t *testing.T) {
	testCases := []struct {
		name                       string
		userAgent                  string
		wantName, wantType, wantOS string
	}{
		{
			name: "firefox on linux", userAgent: firefoxLinux,
			wantName: "Firefox 121", wantType: "Desktop", wantOS: "Linux",
		},
		{
			name: "edge on windows, read before chrome", userAgent: edgeWindows,
			wantName: "Edge 120", wantType: "Desktop", wantOS: "Windows",
		},
		{
			name: "chrome on windows", userAgent: chromeWindows,
			wantName: "Chrome 120", wantType: "Desktop", wantOS: "Windows",
		},
		{
			name: "safari on an iphone", userAgent: safariIPhone,
			wantName: "Safari 17", wantType: "Mobile", wantOS: "iOS",
		},
		{
			name: "safari on an older ipad", userAgent: safariIPad,
			wantName: "Safari 17", wantType: "Tablet", wantOS: "iOS",
		},
		{
			// Keep this: current iPadOS Safari sends a desktop macOS User-Agent and is
			// labelled a macOS desktop. That is the browser's own claim, and RFC 9110 10.1.5
			// says a recipient may assume a masquerading user agent means it.
			name: "safari on a current ipad, which claims macOS", userAgent: safariIPadDesktopMode,
			wantName: "Safari 17", wantType: "Desktop", wantOS: "macOS",
		},
		{
			// Frozen: every Android phone sends "Android 10; K" whatever it is, which is why
			// decision 3 keeps no OS version on either path.
			name: "chrome on an android phone", userAgent: chromeAndroidPhone,
			wantName: "Chrome 120", wantType: "Mobile", wantOS: "Android",
		},
		{
			name: "chrome on an android tablet, which omits Mobile", userAgent: chromeAndroidTablet,
			wantName: "Chrome 120", wantType: "Tablet", wantOS: "Android",
		},
		{
			// Chrome on iOS is Safari's engine under a CriOS token, read before Chrome/ so it
			// is not mistaken for desktop Chrome.
			name: "chrome on ios", userAgent: chromeIOS,
			wantName: "Chrome 120", wantType: "Mobile", wantOS: "iOS",
		},
		{
			// CrOS is read before Linux, which the same header also says.
			name: "chrome on chrome os", userAgent: chromeChromeOS,
			wantName: "Chrome 120", wantType: "Desktop", wantOS: "Chrome OS",
		},
		{
			// Keep this: the old parser answered "Googlebot 2.1" and the type "Bot". Decision
			// 3 drops Bot, because no crawler completes a login ceremony, and the first
			// product token of this header is Mozilla/5.0 rather than the bot's own.
			name: "a crawler", userAgent: googlebot,
			wantName: "Mozilla 5.0", wantType: "unknown", wantOS: "",
		},
		{
			name: "curl", userAgent: curlAgent,
			wantName: "curl 8.5.0", wantType: "unknown", wantOS: "",
		},
		{
			name: "go's http client", userAgent: "Go-http-client/1.1",
			wantName: "Go-http-client 1.1", wantType: "unknown", wantOS: "",
		},
		{
			// Keep this: two integration fixtures fake a second device by sending a token no
			// browser list will ever recognise, and the sweep now keys on the raw header, so
			// the label only has to stay distinct rather than meaningful. A fallback mapping
			// every unrecognised header to one label would make both fixtures pass for the
			// wrong reason.
			name: "an invented token, as the integration fixtures send", userAgent: "goiabada-d2-second-device",
			wantName: "goiabada-d2-second-device", wantType: "unknown", wantOS: "",
		},
		{
			name: "garbage", userAgent: "not-a-real-user-agent",
			wantName: "not-a-real-user-agent", wantType: "unknown", wantOS: "",
		},
		{
			// RFC 9110 10.1.5 puts a product first and allows comments after it, so a header
			// opening with a comment matches no product token and stays Unknown.
			name: "a comment before any product", userAgent: "(comment first) Foo/1",
			wantName: "Unknown", wantType: "unknown", wantOS: "",
		},
		{
			name: "an empty User-Agent header", userAgent: "",
			wantName: "Unknown", wantType: "unknown", wantOS: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			name, deviceType, os := Labels(newRequest(map[string]string{"User-Agent": tc.userAgent}))

			assert.Equal(t, tc.wantName, name)
			assert.Equal(t, tc.wantType, deviceType)
			assert.Equal(t, tc.wantOS, os)
		})
	}
}

// No User-Agent header at all, which is the one case the table above cannot express: a row
// there always sets the header, even to the empty string. RFC 9110 10.1.5 only says a user
// agent SHOULD send one.
func TestLabels_NoUserAgentHeader(t *testing.T) {
	name, deviceType, os := Labels(newRequest(nil))

	assert.Equal(t, "Unknown", name)
	assert.Equal(t, "unknown", deviceType)
	assert.Equal(t, "", os)
}

// Each label is cut to its own column, so no header can make the session insert fail on a
// width. device_type is not exercised here because every value it can take is one of four
// short literals; device_name and device_os both take attacker-chosen text.
func TestLabels_EachLabelIsCutToItsColumn(t *testing.T) {
	t.Run("a 300-byte product token is cut to device_name's 256", func(t *testing.T) {
		token := strings.Repeat("x", 300)

		name, _, _ := Labels(newRequest(map[string]string{"User-Agent": token}))

		assert.Len(t, name, 256)
		assert.Equal(t, strings.Repeat("x", 256), name)
	})

	t.Run("a 300-byte brand is cut to device_name's 256", func(t *testing.T) {
		name, _, _ := Labels(newRequest(map[string]string{
			"Sec-CH-UA": `"` + strings.Repeat("b", 300) + `";v="120"`,
		}))

		assert.Len(t, name, 256)
		assert.Equal(t, strings.Repeat("b", 256), name)
	})

	t.Run("a 100-byte platform is cut to device_os's 64", func(t *testing.T) {
		_, _, os := Labels(newRequest(map[string]string{
			"Sec-CH-UA":          `"Google Chrome";v="120"`,
			"Sec-CH-UA-Platform": `"` + strings.Repeat("p", 100) + `"`,
		}))

		assert.Len(t, os, 64)
		assert.Equal(t, strings.Repeat("p", 64), os)
	})

	t.Run("a multibyte label is cut on a rune boundary", func(t *testing.T) {
		// 3-byte runes: 256 is not a multiple of 3, so a byte cut would split the 86th rune
		// and hand the column something that is not UTF-8 at all.
		name, _, _ := Labels(newRequest(map[string]string{
			"Sec-CH-UA": `"` + strings.Repeat("é", 200) + `";v="1"`,
		}))

		assert.True(t, utf8.ValidString(name), "a cut label must still be valid UTF-8")
		assert.LessOrEqual(t, len(name), 256)
	})
}

// The same request must always yield the same triple: the session row is written once from
// these values and read back beside rows written from another request's.
func TestLabels_AreStableForTheSameRequest(t *testing.T) {
	req := newRequest(map[string]string{
		"Sec-CH-UA":          `"Google Chrome";v="120", "Not?A_Brand";v="24"`,
		"Sec-CH-UA-Mobile":   "?0",
		"Sec-CH-UA-Platform": `"Windows"`,
		"User-Agent":         chromeWindows,
	})

	for i := 0; i < 3; i++ {
		name, deviceType, os := Labels(req)

		assert.Equal(t, "Chrome 120", name)
		assert.Equal(t, "Desktop", deviceType)
		assert.Equal(t, "Windows", os)
	}
}

// Decision 3 kept the OS label rather than dropping it, because without it the one job the
// labels have -- letting a person tell their own sessions apart -- fails for the common case
// of the same browser on two machines. This is the case that would have been lost.
func TestLabels_TheSameBrowserOnTwoPlatformsReadsDifferently(t *testing.T) {
	hints := func(platform string) map[string]string {
		return map[string]string{
			"Sec-CH-UA":          `"Google Chrome";v="120", "Chromium";v="120", "Not?A_Brand";v="24"`,
			"Sec-CH-UA-Mobile":   "?0",
			"Sec-CH-UA-Platform": platform,
		}
	}

	windowsName, windowsType, windowsOS := Labels(newRequest(hints(`"Windows"`)))
	macName, macType, macOS := Labels(newRequest(hints(`"macOS"`)))

	assert.Equal(t, windowsName, macName, "the browser is the same on both")
	assert.Equal(t, windowsType, macType)
	assert.NotEqual(t, windowsOS, macOS, "the platform is the only thing telling them apart")
}

// Bound is what keeps a request header inside the columns that store it: 512 bytes for
// user_sessions.user_agent and codes.user_agent, and the three label widths above. Every
// row here is a rule the storage layer depends on, so none of them is cosmetic (#281).
func TestBound(t *testing.T) {
	testCases := []struct {
		name  string
		in    string
		max   int
		want  string
		bytes int
	}{
		{
			name:  "empty in, empty out",
			in:    "",
			max:   512,
			want:  "",
			bytes: 0,
		},
		{
			name:  "shorter than the bound is untouched",
			in:    "curl/8.5.0",
			max:   512,
			want:  "curl/8.5.0",
			bytes: 10,
		},
		{
			name:  "exactly at the bound is untouched",
			in:    strings.Repeat("a", 512),
			max:   512,
			want:  strings.Repeat("a", 512),
			bytes: 512,
		},
		{
			name:  "one byte over the bound is cut",
			in:    strings.Repeat("a", 513),
			max:   512,
			want:  strings.Repeat("a", 512),
			bytes: 512,
		},
		{
			// A 4-byte rune straddling the bound is dropped whole rather than halved,
			// so the result is still valid UTF-8 and still inside the column.
			name:  "a 4-byte rune straddling the bound is dropped whole",
			in:    "aa\U0001F600",
			max:   4,
			want:  "aa",
			bytes: 2,
		},
		{
			// The same rule at the widest straddle: only the first byte of the rune is
			// inside the bound, so three bytes of headroom are given up to keep it valid.
			name:  "a 4-byte rune with one byte inside the bound is dropped whole",
			in:    "aaa\U0001F600",
			max:   4,
			want:  "aaa",
			bytes: 3,
		},
		{
			name:  "a 2-byte rune ending exactly at the bound is kept",
			in:    "aaéb",
			max:   4,
			want:  "aaé",
			bytes: 4,
		},
		{
			// RFC 9110 10.1.5 admits obs-text in a User-Agent, and PostgreSQL and MySQL
			// both refuse the insert outright rather than storing a stray latin1 byte.
			name:  "a lone 0xE9 becomes U+FFFD",
			in:    "\xe9 Chrome",
			max:   512,
			want:  "� Chrome",
			bytes: 10,
		},
		{
			// The order of the two operations, pinned: repair first, then cut. A
			// cut-then-repair implementation returns 8 bytes here, because it finds the
			// input already inside the bound and then grows each byte into a 3-byte
			// U+FFFD, handing the column a value it refuses.
			name:  "repair runs before the cut, not after",
			in:    "\xe9a\xe9a",
			max:   4,
			want:  "�a",
			bytes: 4,
		},
		{
			name:  "a zero bound gives the empty string",
			in:    "curl/8.5.0",
			max:   0,
			want:  "",
			bytes: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := Bound(tc.in, tc.max)

			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.bytes, len(got))
			assert.LessOrEqual(t, len(got), tc.max)
			assert.True(t, utf8.ValidString(got), "Bound must always return valid UTF-8")
		})
	}
}

func TestRaw(t *testing.T) {
	t.Run("the header is returned as sent", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("User-Agent", chromeWindows)

		assert.Equal(t, chromeWindows, Raw(req))
	})

	t.Run("no header gives the empty string", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Del("User-Agent")

		assert.Equal(t, "", Raw(req))
	})

	t.Run("an over-long header is bounded to 512 bytes", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("User-Agent", strings.Repeat("a", 600))

		got := Raw(req)

		assert.Len(t, got, 512)
		assert.Equal(t, strings.Repeat("a", 512), got)
	})
}

// Every prefix of a header carrying every bare-item form, and every prefix of a platform hint.
//
// The reader walks a byte at a time and several of its steps look ahead, so the failure it is
// prone to is indexing past a field that stopped early -- and a field stops wherever the sender
// chose, since both hints are request headers. That is not hypothetical: `v=@` was a panic
// inside Labels, reachable by anyone able to send a header, because parseDate stepped over the
// "@" and handed parseNumber an index one past the end.
//
// Truncation is the whole family rather than that one row: every form's parser is entered here
// and then cut off at each byte in turn, so a look-ahead added to any of them is covered by
// this test on the day it is written. The assertion is only that Labels answers rather than
// panics, and that it answers the same thing twice; which label a truncated header produces is
// the tables above, and pinning it here would make this fail for the wrong reason.
func TestLabels_NoPrefixOfAHintCanPanic(t *testing.T) {
	// One member of each bare-item form RFC 9651 4.2.3.1 dispatches on: string, integer,
	// decimal, negative, token, byte sequence, boolean, date, display string.
	const brands = `"Google Chrome";v="120";a=1;b=1.5;c=-2;d=tok;e=:QQ==:;f=?1;g=@1659578233;` +
		`h=%"caf%c3%a9", "Chromium";v="120"`

	for i := 0; i <= len(brands); i++ {
		prefix := brands[:i]
		t.Run("brands cut at "+strconv.Itoa(i), func(t *testing.T) {
			name, deviceType, os := Labels(newRequest(map[string]string{
				"Sec-CH-UA":  prefix,
				"User-Agent": firefoxLinux,
			}))
			// Whatever it answered, it answers it again: a reader that consumed a different
			// number of bytes on the second pass has state the first pass left behind.
			name2, deviceType2, os2 := Labels(newRequest(map[string]string{
				"Sec-CH-UA":  prefix,
				"User-Agent": firefoxLinux,
			}))
			assert.Equal(t, name, name2)
			assert.Equal(t, deviceType, deviceType2)
			assert.Equal(t, os, os2)
		})
	}

	const plat = `"Windows"`
	for i := 0; i <= len(plat); i++ {
		prefix := plat[:i]
		t.Run("platform cut at "+strconv.Itoa(i), func(t *testing.T) {
			assert.NotPanics(t, func() {
				Labels(newRequest(map[string]string{
					"Sec-CH-UA":          `"Google Chrome";v="120"`,
					"Sec-CH-UA-Platform": prefix,
					"User-Agent":         firefoxLinux,
				}))
			})
		})
	}
}

// The one truncation that was a crash, named on its own so a failure says what broke rather
// than pointing at an index in the sweep above. "@" starts a Date (RFC 9651 4.2.3.1 step 6)
// and 4.2.9 discards it before parsing an sf-integer, so a field ending at the "@" leaves the
// integer parser one byte past the end.
func TestLabels_ADateParameterCutOffAtTheAtSignIsRefused(t *testing.T) {
	name, deviceType, os := Labels(newRequest(map[string]string{
		"Sec-CH-UA":  `"Google Chrome";v=@`,
		"User-Agent": firefoxLinux,
	}))

	assert.Equal(t, "Firefox 121", name)
	assert.Equal(t, "Desktop", deviceType)
	assert.Equal(t, "Linux", os)
}
