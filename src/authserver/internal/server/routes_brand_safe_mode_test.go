package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/routing"
)

// GOIABADA_AUTHSERVER_BRAND_SAFE_MODE draws every page in safe mode, linking the brand's safe
// stylesheet, and the public settings say so and publish the safe links as the brand's own (#816
// decision 3). Off, both are as usual.
func TestRegisterRoutes_TheSafeModeSwitchReachesEveryPageAndThePublicSettings(t *testing.T) {
	brand := record.NewBrand("Shop", record.BrandAppearanceAuto, "plum")
	brand.Id = 7
	brand.CustomCSS = ".auth-card { border-width: 3px; }"

	for _, tc := range []struct {
		name     string
		switchOn bool
		wantPage string
	}{
		{"on", true, `^/brand/7/safe-stylesheet\.css\?v=[0-9a-f]{12}$`},
		{"off", false, `^/brand/7/stylesheet\.css\?v=[0-9a-f]{12}$`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("PoolStats").Return(testPoolStats).Maybe()
			database.On("GetDefaultBrand", mock.Anything, mock.Anything).Return(&brand, nil).Maybe()
			database.On("GetClientPageBrand", mock.Anything, mock.Anything, mock.Anything).Return(&brand, nil).Maybe()
			database.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).
				Return(&record.Settings{Id: 1, AppName: "Goiabada"}, nil).Maybe()
			cfg := &config.Config{}
			cfg.AuthServer.ProfilePictureMaxSizeBytes = testProfilePictureMaxSizeBytes
			cfg.AuthServer.BrandSafeMode = tc.switchOn
			s := NewServer(routing.New(), database, newTestSessionStore(), nil, nil, cfg, testTokenProofs(t))
			s.registerRoutes()

			// A page no route draws, answered at the root.
			rr := httptest.NewRecorder()
			s.router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/no-such-page", nil))
			require.Equal(t, http.StatusNotFound, rr.Code)
			doc, err := goquery.NewDocumentFromReader(strings.NewReader(rr.Body.String()))
			require.NoError(t, err)
			var stylesheets []string
			doc.Find(`link[rel="stylesheet"]`).Each(func(_ int, link *goquery.Selection) {
				href, _ := link.Attr("href")
				stylesheets = append(stylesheets, href)
			})
			require.Len(t, stylesheets, 2, "main.css, then the brand's stylesheet")
			assert.Regexp(t, tc.wantPage, stylesheets[1])

			rr = httptest.NewRecorder()
			s.router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/public/settings", nil))
			require.Equal(t, http.StatusOK, rr.Code)
			var body struct {
				Brand map[string]any `json:"brand"`
			}
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
			assert.Equal(t, tc.switchOn, body.Brand["safeMode"])
			stylesheetURL, _ := body.Brand["stylesheetUrl"].(string)
			assert.Regexp(t, strings.TrimPrefix(tc.wantPage, "^"), stylesheetURL)
		})
	}
}
