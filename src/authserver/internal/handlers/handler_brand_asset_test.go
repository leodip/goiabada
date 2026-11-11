package handlers

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// A brand asset is answered to anyone, as a static file is (#813): kept for a year when asked for
// by its current fingerprint and five minutes otherwise, under the type its upload was validated
// as, with nosniff. A font is granted to the admin console's origin, and to no other, so the
// console's pages can draw it (decision 8); an image carries no grant.

const consoleOrigin = "https://console.example.com"

var logoAsset = record.BrandAsset{
	Id: 12, Kind: record.BrandAssetKindLogo, ContentType: "image/png", Fingerprint: "0a1b2c3d4e5f",
	Width: 10, Height: 10, Content: []byte("\x89PNG\r\n\x1a\n-logo-bytes"),
}

var fontAsset = record.BrandAsset{
	Id: 13, Kind: record.BrandAssetKindFont, ContentType: "font/woff2", Fingerprint: "f0e1d2c3b4a5",
	Content: []byte("wOF2-font-bytes"),
}

func serveBrandAsset(t *testing.T, asset *record.BrandAsset, id, query string) *httptest.ResponseRecorder {
	t.Helper()
	database := datamocks.NewDatabase(t)
	if asset != nil {
		database.On("GetBrandAssetById", mock.Anything, (*sql.Tx)(nil), asset.Id).Return(asset, nil).Once()
	}
	req := httptest.NewRequest(http.MethodGet, "/brand-assets/"+id+query, nil)
	req.SetPathValue("id", id)
	rr := httptest.NewRecorder()
	HandleBrandAssetGet(handlersmocks.NewPageRenderer(t), database, consoleOrigin).ServeHTTP(rr, req)
	return rr
}

func TestHandleBrandAssetGet_AnswersTheBytesUnderTheirValidatedType(t *testing.T) {
	rr := serveBrandAsset(t, &logoAsset, "12", "?v=0a1b2c3d4e5f")

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "image/png", rr.Header().Get("Content-Type"))
	assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "19", rr.Header().Get("Content-Length"))
	assert.Equal(t, "\x89PNG\r\n\x1a\n-logo-bytes", rr.Body.String())
	assert.Empty(t, rr.Header().Values("Set-Cookie"))

	rr = serveBrandAsset(t, &fontAsset, "13", "?v=f0e1d2c3b4a5")

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "font/woff2", rr.Header().Get("Content-Type"))
	assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "wOF2-font-bytes", rr.Body.String())
}

// Only the current fingerprint, named once, is kept for a year: a URL never holds for a year what
// it does not name.
func TestHandleBrandAssetGet_OnlyTheCurrentFingerprintIsCachedForAYear(t *testing.T) {
	tests := []struct {
		name  string
		query string
		cache string
	}{
		{"the current fingerprint", "?v=0a1b2c3d4e5f", "public, max-age=31536000, immutable"},
		{"a stale fingerprint", "?v=ffffffffffff", "public, max-age=300"},
		{"no fingerprint", "", "public, max-age=300"},
		{"an empty fingerprint", "?v=", "public, max-age=300"},
		{"the fingerprint named twice", "?v=0a1b2c3d4e5f&v=0a1b2c3d4e5f", "public, max-age=300"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := serveBrandAsset(t, &logoAsset, "12", tt.query)

			require.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, tt.cache, rr.Header().Get("Cache-Control"))
			assert.Equal(t, "\x89PNG\r\n\x1a\n-logo-bytes", rr.Body.String(), "the current bytes, whatever the fingerprint")
		})
	}
}

// The font grant names the console's origin alone and carries no credentials; an image has none.
func TestHandleBrandAssetGet_GrantsAFontToTheConsoleAlone(t *testing.T) {
	rr := serveBrandAsset(t, &fontAsset, "13", "?v=f0e1d2c3b4a5")

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, []string{consoleOrigin}, rr.Header().Values("Access-Control-Allow-Origin"))
	assert.Empty(t, rr.Header().Values("Access-Control-Allow-Credentials"))

	for _, image := range []record.BrandAsset{
		logoAsset,
		{Id: 14, Kind: record.BrandAssetKindFavicon, ContentType: "image/png", Fingerprint: "aaaaaaaaaaaa", Content: []byte("x")},
		{Id: 15, Kind: record.BrandAssetKindBackground, ContentType: "image/jpeg", Fingerprint: "bbbbbbbbbbbb", Content: []byte("x")},
	} {
		t.Run(string(image.Kind), func(t *testing.T) {
			rr := serveBrandAsset(t, &image, strconv.FormatInt(image.Id, 10), "")

			require.Equal(t, http.StatusOK, rr.Code)
			assert.Empty(t, rr.Header().Values("Access-Control-Allow-Origin"))
		})
	}
}

func TestHandleBrandAssetGet_NotFound(t *testing.T) {
	t.Run("no such asset", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetBrandAssetById", mock.Anything, (*sql.Tx)(nil), int64(99)).Return(nil, nil).Once()
		req := httptest.NewRequest(http.MethodGet, "/brand-assets/99", nil)
		req.SetPathValue("id", "99")
		rr := httptest.NewRecorder()
		HandleBrandAssetGet(handlersmocks.NewPageRenderer(t), database, consoleOrigin).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
		assert.Empty(t, rr.Header().Values("Access-Control-Allow-Origin"))
	})

	for _, id := range []string{"abc", "0", "-1", "1.5"} {
		t.Run("the id "+id, func(t *testing.T) {
			rr := serveBrandAsset(t, nil, id, "")

			assert.Equal(t, http.StatusNotFound, rr.Code)
		})
	}
}

func TestHandleBrandAssetGet_AReadThatFailsIsA500(t *testing.T) {
	database := datamocks.NewDatabase(t)
	failure := errors.New("connection refused")
	database.On("GetBrandAssetById", mock.Anything, (*sql.Tx)(nil), int64(12)).Return(nil, failure).Once()
	pageRenderer := handlersmocks.NewPageRenderer(t)
	pageRenderer.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		return errors.Is(err, failure)
	})).Once()

	req := httptest.NewRequest(http.MethodGet, "/brand-assets/12", nil)
	req.SetPathValue("id", "12")
	HandleBrandAssetGet(pageRenderer, database, consoleOrigin).ServeHTTP(httptest.NewRecorder(), req)
}

// With no console origin to grant, a font is answered with no grant at all, never a wildcard.
func TestHandleBrandAssetGet_NoOriginToGrantGrantsNothing(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetBrandAssetById", mock.Anything, (*sql.Tx)(nil), int64(13)).Return(&fontAsset, nil).Once()
	req := httptest.NewRequest(http.MethodGet, "/brand-assets/13", nil)
	req.SetPathValue("id", "13")
	rr := httptest.NewRecorder()
	HandleBrandAssetGet(handlersmocks.NewPageRenderer(t), database, "").ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Empty(t, rr.Header().Values("Access-Control-Allow-Origin"))
}
