package server

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Download data button's route, through the real route table and the whole adminAuth chain,
// against an auth server answering the export as it does, compressed (#781 decisions 5 and 7).
// The browser receives the auth server's bytes and the headers that describe them, and only a
// same-origin form starts the download: a link another site could follow, or its own form, is not
// served.
func TestInitRoutes_DownloadDataPassesTheUsersExportToTheBrowser(t *testing.T) {
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	_, err := zw.Write([]byte(`{"formatVersion":1,"identifiers":{"id":7}}`))
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	var mu sync.Mutex
	var asked []string
	var acceptEncoding string
	s, cookies := newSignedInConsole(t, "openid authserver:manage", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.Method+" "+r.URL.Path)
		acceptEncoding = r.Header.Get("Accept-Encoding")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Vary", "Accept-Encoding")
		w.Header().Set("Content-Disposition", `attachment; filename="user-7-2026-11-05.json"`)
		_, _ = w.Write(compressed.Bytes())
	})
	serve := func(method string, headers map[string]string) *httptest.ResponseRecorder {
		mu.Lock()
		asked = nil
		mu.Unlock()
		req := httptest.NewRequest(method, "/admin/users/7/export", nil)
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		for name, value := range headers {
			req.Header.Set(name, value)
		}
		rec := httptest.NewRecorder()
		s.router.ServeHTTP(rec, req)
		return rec
	}
	exportsAsked := func() []string {
		mu.Lock()
		defer mu.Unlock()
		var exports []string
		for _, a := range asked {
			if a == "GET /api/v1/admin/users/7/export" {
				exports = append(exports, a)
			}
		}
		return exports
	}

	t.Run("the form on the user's page downloads the file", func(t *testing.T) {
		rec := serve(http.MethodPost, map[string]string{"Sec-Fetch-Site": "same-origin"})

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Len(t, exportsAsked(), 1)
		mu.Lock()
		assert.Equal(t, "gzip", acceptEncoding, "the console asks for the compressed answer")
		mu.Unlock()
		assert.Equal(t, compressed.Bytes(), rec.Body.Bytes(), "the bytes as the auth server sent them")
		assert.Equal(t, "gzip", rec.Header().Get("Content-Encoding"), "which the browser unpacks")
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
		assert.Equal(t, `attachment; filename="user-7-2026-11-05.json"`, rec.Header().Get("Content-Disposition"))
		assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	})

	t.Run("another site's form is refused", func(t *testing.T) {
		rec := serve(http.MethodPost, map[string]string{
			"Origin":         "https://elsewhere.example",
			"Sec-Fetch-Site": "cross-site",
		})

		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Empty(t, exportsAsked(), "no export is asked for, and none is audited")
		assert.Empty(t, rec.Header().Get("Content-Disposition"))
	})

	t.Run("a link is not served", func(t *testing.T) {
		rec := serve(http.MethodGet, map[string]string{"Sec-Fetch-Site": "cross-site"})

		assert.NotEqual(t, http.StatusOK, rec.Code)
		assert.Empty(t, exportsAsked(), "no export is asked for, and none is audited")
		assert.Empty(t, rec.Header().Get("Content-Disposition"))
	})
}
