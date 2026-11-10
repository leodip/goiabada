package server

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The long cache a static file's current fingerprint earns, and the five minutes everything else
// keeps (#810 decision 7).
const (
	staticLongCache  = "public, max-age=31536000, immutable"
	staticShortCache = "public, max-age=300"
)

// linkedStaticURL matches a static file's URL as a page links it, with its fingerprint.
var linkedStaticURL = regexp.MustCompile(`"(/static/[^"?]+)\?v=([^"&]+)"`)

// A static file requested by the fingerprint a page links it with, which is the file's current
// one, is cacheable for a year and immutable; the URL changes whenever the file does.
func TestRegisterRoutes_AStaticFileByItsCurrentFingerprintIsKeptForAYear(t *testing.T) {
	s := newRoutingTestServer(t, newRoutingDatabase(t))

	page := serveRouting(s, http.MethodGet, "/no/such/page", nil)
	assertNotFoundPage(t, page)
	linked := linkedStaticURL.FindAllStringSubmatch(page.Body.String(), -1)
	paths := make([]string, 0, len(linked))
	for _, link := range linked {
		paths = append(paths, link[1])
	}
	require.Contains(t, paths, "/static/main.css", "the page links its stylesheet by fingerprint")
	require.Contains(t, paths, "/static/utils.js", "and its script")

	for _, link := range linked {
		target := link[1] + "?v=" + link[2]
		t.Run(target, func(t *testing.T) {
			before := time.Now().Truncate(time.Second)
			rr := serveRouting(s, http.MethodGet, target, nil)

			require.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, staticLongCache, rr.Header().Get("Cache-Control"))
			assert.Equal(t, []string{"Accept-Encoding"}, rr.Header().Values("Vary"))
			expires, err := http.ParseTime(rr.Header().Get("Expires"))
			require.NoError(t, err, "Expires is an HTTP date")
			assert.WithinRange(t, expires, before.Add(365*24*time.Hour), time.Now().Add(365*24*time.Hour+time.Second))
		})
	}
}

// Any other request for a static file, by a stale fingerprint, a malformed one or none, gets the
// current file kept five minutes, and never the year: a URL holds for a year only the content it
// names.
func TestRegisterRoutes_AStaticFileByAnyOtherURLIsKeptForFiveMinutes(t *testing.T) {
	s := newRoutingTestServer(t, newRoutingDatabase(t))

	page := serveRouting(s, http.MethodGet, "/no/such/page", nil)
	assertNotFoundPage(t, page)
	current := map[string]string{}
	for _, link := range linkedStaticURL.FindAllStringSubmatch(page.Body.String(), -1) {
		current[link[1]] = link[2]
	}
	css, js := current["/static/main.css"], current["/static/utils.js"]
	require.NotEmpty(t, css)
	require.NotEmpty(t, js)
	require.NotEqual(t, css, js)

	for _, target := range []string{
		"/static/main.css",
		"/static/main.css?v=",
		"/static/main.css?v=000000000000",
		"/static/main.css?v=" + js,
		"/static/main.css?v=" + strings.ToUpper(css),
		"/static/main.css?v=" + css + "0",
		"/static/main.css?v=" + css[:len(css)-1],
		"/static/main.css?v=" + css + "&v=" + css,
		"/static/main.css?w=" + css,
		"/static/favicon/favicon.ico",
	} {
		t.Run(target, func(t *testing.T) {
			before := time.Now().Truncate(time.Second)
			rr := serveRouting(s, http.MethodGet, target, nil)

			require.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, staticShortCache, rr.Header().Get("Cache-Control"))
			expires, err := http.ParseTime(rr.Header().Get("Expires"))
			require.NoError(t, err, "Expires is an HTTP date")
			assert.WithinRange(t, expires, before.Add(5*time.Minute), time.Now().Add(5*time.Minute+time.Second))
		})
	}

	missing := serveRouting(s, http.MethodGet, "/static/no-such-file.css?v="+css, nil)
	assert.Equal(t, http.StatusNotFound, missing.Code)
	assert.NotContains(t, missing.Header().Get("Cache-Control"), "immutable")
}
