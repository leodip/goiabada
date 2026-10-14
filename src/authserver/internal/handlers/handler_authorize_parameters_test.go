package handlers

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The request's parameters are read from one url.Values, the query and a form body merged as
// r.FormValue merges them, the query's value first.
func TestAuthorizeParameters(t *testing.T) {
	t.Run("the query and the form body are one source", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/authorize?client_id=from-query&state=query-state",
			strings.NewReader("redirect_uri="+url.QueryEscape("https://example.com/cb")+"&state=body-state"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		params, err := authorizeParameters(req)
		require.NoError(t, err)

		assert.Equal(t, "from-query", params.Get("client_id"))
		assert.Equal(t, "https://example.com/cb", params.Get("redirect_uri"))
		assert.Equal(t, "body-state", params.Get("state"), "the body's value comes first, as r.FormValue answers")
		assert.Equal(t, req.FormValue("state"), params.Get("state"))
	})

	t.Run("a form already parsed is read as it stands", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/authorize?client_id=from-query", nil)
		req.Form = url.Values{"client_id": {"parsed-earlier"}}

		params, err := authorizeParameters(req)
		require.NoError(t, err)
		assert.Equal(t, "parsed-earlier", params.Get("client_id"))
	})

	t.Run("a multipart body is read, as r.FormValue reads it", func(t *testing.T) {
		var body bytes.Buffer
		form := multipart.NewWriter(&body)
		require.NoError(t, form.WriteField("state", "multipart-state"))
		require.NoError(t, form.Close())
		req := httptest.NewRequest(http.MethodPost, "/auth/authorize?client_id=from-query", &body)
		req.Header.Set("Content-Type", form.FormDataContentType())

		params, err := authorizeParameters(req)
		require.NoError(t, err)
		assert.Equal(t, "from-query", params.Get("client_id"))
		assert.Equal(t, "multipart-state", params.Get("state"))
	})

	// Until #228 a parse failure was ignored and the field holding it dropped, as r.FormValue does;
	// now it is returned, and HandleAuthorizeGet answers it on the refusal page.
	t.Run("a body that does not parse is an error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/authorize?client_id=from-query",
			strings.NewReader("state=%zz"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		_, err := authorizeParameters(req)
		assert.Error(t, err)
	})

	t.Run("a query that does not parse is an error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/authorize?client_id=from-query&state=%zz", nil)

		_, err := authorizeParameters(req)
		assert.Error(t, err)
	})

	t.Run("a multipart body that does not parse is an error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/authorize", strings.NewReader("not a multipart body"))
		req.Header.Set("Content-Type", "multipart/form-data; boundary=xyz")

		_, err := authorizeParameters(req)
		assert.Error(t, err)
	})
}
