package useragent

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// These three functions populate UserSession.DeviceName / DeviceType / DeviceOS.
// StartNewUserSession compares all three (plus the IP) to decide which older
// sessions a fresh login supersedes, so their exact output is load-bearing and
// not merely cosmetic.

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
