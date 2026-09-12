package useragent

import (
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
)

// GetDeviceName / GetDeviceType / GetDeviceOS populate UserSession.DeviceName /
// DeviceType / DeviceOS, which are display only: StartNewUserSession keys its
// "same device" sweep on the raw User-Agent header and the IP address, never on a
// parsed label (#281). The rows below pin today's output so a change of shape is
// a deliberate edit rather than a silent one.
//
// Bound and Raw below them are load-bearing: Bound is the only thing keeping a
// request header inside the columns that store it.

const (
	chromeWindows = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	firefoxLinux = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
	safariIPhone = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 " +
		"(KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1"
	safariIPad = "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 " +
		"(KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1"
	chromeAndroid = "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
	googlebot = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	curlAgent = "curl/8.5.0"
)

func TestGetDeviceName(t *testing.T) {
	testCases := []struct {
		name      string
		userAgent string
		want      string
	}{
		{
			name:      "desktop browser has no device segment",
			userAgent: chromeWindows,
			want:      "Chrome 120.0.0.0",
		},
		{
			name:      "firefox on linux",
			userAgent: firefoxLinux,
			want:      "Firefox 121.0",
		},
		{
			name:      "phone includes the device in parentheses",
			userAgent: safariIPhone,
			want:      "Safari 17.1 (iPhone)",
		},
		{
			name:      "tablet includes the device in parentheses",
			userAgent: safariIPad,
			want:      "Safari 17.1 (iPad)",
		},
		{
			name:      "android names the handset",
			userAgent: chromeAndroid,
			want:      "Chrome 120.0.0.0 (Pixel 7)",
		},
		{
			name:      "bot",
			userAgent: googlebot,
			want:      "Googlebot 2.1",
		},
		{
			name:      "non-browser client",
			userAgent: curlAgent,
			want:      "curl 8.5.0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("User-Agent", tc.userAgent)

			assert.Equal(t, tc.want, GetDeviceName(req))
		})
	}
}

// With no User-Agent the name is a single space rather than the empty string,
// because it is formatted from two empty fields. Worth knowing: every client
// that sends no User-Agent shares this same device name, so on a shared IP such
// sessions look like the same device to StartNewUserSession and supersede each
// other.
func TestGetDeviceName_MissingUserAgent(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Del("User-Agent")

	assert.Equal(t, " ", GetDeviceName(req))
}

func TestGetDeviceName_EmptyUserAgentHeader(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "")

	assert.Equal(t, " ", GetDeviceName(req))
}

// The column is bounded, so an over-long value is truncated rather than
// rejected or allowed to overflow.
func TestGetDeviceName_TruncatedTo256Characters(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent",
		"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/"+strings.Repeat("9", 300))

	name := GetDeviceName(req)

	assert.Len(t, name, 256)
	assert.True(t, strings.HasPrefix(name, "Firefox "))
}

func TestGetDeviceType(t *testing.T) {
	testCases := []struct {
		name      string
		userAgent string
		want      string
	}{
		{"windows desktop", chromeWindows, "Desktop"},
		{"linux desktop", firefoxLinux, "Desktop"},
		{"iphone", safariIPhone, "Mobile"},
		{"android phone", chromeAndroid, "Mobile"},
		{"ipad", safariIPad, "Tablet"},
		{"crawler", googlebot, "Bot"},
		{"command line client", curlAgent, "unknown"},
		{"garbage", "not-a-real-user-agent", "unknown"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("User-Agent", tc.userAgent)

			assert.Equal(t, tc.want, GetDeviceType(req))
		})
	}
}

func TestGetDeviceType_MissingUserAgent(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Del("User-Agent")

	assert.Equal(t, "unknown", GetDeviceType(req))
}

func TestGetDeviceOS(t *testing.T) {
	testCases := []struct {
		name      string
		userAgent string
		want      string
	}{
		{"windows", chromeWindows, "Windows 10.0"},
		{"linux", firefoxLinux, "Linux x86_64"},
		{"ios on a phone", safariIPhone, "iOS 17.1"},
		{"ios on a tablet", safariIPad, "iOS 17.1"},
		{"android", chromeAndroid, "Android 13"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("User-Agent", tc.userAgent)

			assert.Equal(t, tc.want, GetDeviceOS(req))
		})
	}
}

// As with the device name, an unknown OS formats to a single space.
func TestGetDeviceOS_UnknownOS(t *testing.T) {
	for _, userAgent := range []string{curlAgent, googlebot, ""} {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("User-Agent", userAgent)

		assert.Equal(t, " ", GetDeviceOS(req))
	}
}

func TestGetDeviceOS_TruncatedTo64Characters(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent",
		"Mozilla/5.0 (X11; Linux "+strings.Repeat("x", 200)+"; rv:121.0) Gecko/20100101 Firefox/121.0")

	os := GetDeviceOS(req)

	assert.Len(t, os, 64)
	assert.True(t, strings.HasPrefix(os, "Linux "))
}

// The same request must always yield the same triple, since session matching
// depends on comparing values captured at different times.
func TestDeviceFieldsAreStableForTheSameUserAgent(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", chromeWindows)

	for i := 0; i < 3; i++ {
		assert.Equal(t, "Chrome 120.0.0.0", GetDeviceName(req))
		assert.Equal(t, "Desktop", GetDeviceType(req))
		assert.Equal(t, "Windows 10.0", GetDeviceOS(req))
	}
}

// Two different browsers on the same OS must not collapse to the same device
// name, otherwise a login in one would supersede the session of the other.
func TestDifferentBrowsersProduceDifferentDeviceNames(t *testing.T) {
	chromeReq := httptest.NewRequest("GET", "/", nil)
	chromeReq.Header.Set("User-Agent", chromeWindows)

	firefoxReq := httptest.NewRequest("GET", "/", nil)
	firefoxReq.Header.Set("User-Agent", firefoxLinux)

	assert.NotEqual(t, GetDeviceName(chromeReq), GetDeviceName(firefoxReq))
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
