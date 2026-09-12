package useragent

import (
	"net/http"
	"net/http/httptest"
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
			// The positive control for the escape gate: \" is one of the two escapes RFC 8941
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
			// Gate: RFC 8941 3.3.3, "other characters after '\' MUST cause parsing to fail".
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
			// the field (RFC 8941 3.1). Pinning it takes a contrived header, and the shape is
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
			// no member, and RFC 8941 3.1 has no empty one.
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
			// Gate: RFC 8941 3.3.3 unescaped = %x20-21 / %x23-5B / %x5D-7E, so a control
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
			// Gate: an empty Sec-CH-UA is an empty list, which UA-CH never sends and RFC 8941
			// 3.1 does not admit as a member.
			name: "an empty Sec-CH-UA",
			headers: map[string]string{
				"Sec-CH-UA":  "",
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
		// Gate: RFC 8941 3.3.3 again, the escape rule, on the platform rather than a brand.
		{"an invalid escape", `"Win\dows"`},
		// Gate: nothing may trail the closing quote.
		{"junk after the closing quote", `"Windows" x`},
		// Gate: unterminated.
		{"never closed", `"Windows`},
		// Gate: a control character, unescaped.
		{"a control character", "\"Win\x01dows\""},
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
