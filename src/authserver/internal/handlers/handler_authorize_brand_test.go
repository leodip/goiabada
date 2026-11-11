package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/render"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/web"
)

// A 500 the authorization endpoint answers once the request's client is known is drawn in that
// client's brand, and one answered before, when the address check itself fails, in the default:
// GET's read of the browser's session and POST's park both come after the check (#812).
func TestAuthorize_AFaultOnceTheClientIsKnownKeepsItsBrand(t *testing.T) {
	night := &record.Brand{Id: 7, Name: "Night", Appearance: record.BrandAppearanceDark, Theme: "plum"}
	day := &record.Brand{Id: 12, Name: "Day", Appearance: record.BrandAppearanceLight, Theme: "avocado"}

	for _, tc := range []struct {
		name          string
		method        string
		clientKnown   bool
		wantDataTheme string
		wantBrandHref string
	}{
		{name: "GET, the session read failing after the check", method: http.MethodGet, clientKnown: true,
			wantDataTheme: "light", wantBrandHref: brandStylesheetHrefForTest(t, 12, "avocado")},
		{name: "POST, the park failing after the check", method: http.MethodPost, clientKnown: true,
			wantDataTheme: "light", wantBrandHref: brandStylesheetHrefForTest(t, 12, "avocado")},
		{name: "GET, the check itself failing", method: http.MethodGet, clientKnown: false,
			wantDataTheme: "dark", wantBrandHref: brandStylesheetHrefForTest(t, 7, "plum")},
		{name: "POST, the check itself failing", method: http.MethodPost, clientKnown: false,
			wantDataTheme: "dark", wantBrandHref: brandStylesheetHrefForTest(t, 7, "plum")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("GetDefaultBrand", mock.Anything, mock.Anything).Return(night, nil).Maybe()
			database.On("GetClientPageBrand", mock.Anything, mock.Anything, "test-client").Return(day, nil).Maybe()
			renderer := render.New(web.TemplateFS(), web.StaticFS(), database)

			validator := handlersmocks.NewAuthorizeValidator(t)
			if tc.clientKnown {
				validator.On("ValidateClientAndRedirectURI", mock.Anything, mock.Anything).Return(nil).Once()
			} else {
				validator.On("ValidateClientAndRedirectURI", mock.Anything, mock.Anything).
					Return(errors.New("injected address check fault")).Once()
			}

			var handler http.HandlerFunc
			var req *http.Request
			if tc.method == http.MethodGet {
				if tc.clientKnown {
					database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
						Return(&record.Client{Id: 1, ClientIdentifier: "test-client", Enabled: true}, nil).Once()
					stubRegisteredRedirectURI(database, "https://example.com")
					database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, mock.Anything).
						Return(nil, errors.New("injected session read fault")).Once()
				}
				handler = buildAuthorizeGet(authorizeGetDeps{pageRenderer: renderer, database: database,
					authorizeValidator: validator})
				req = renderableRequest("/auth/authorize?" + validAuthorizeQuery)
			} else {
				if tc.clientKnown {
					database.On("CreateAuthorizeRequest", mock.Anything, mock.Anything, mock.Anything).
						Return(errors.New("injected park fault")).Once()
				}
				handler = buildAuthorizePost(authorizePostDeps{pageRenderer: renderer, database: database,
					authorizeValidator: validator})
				settled := renderableRequest("/auth/authorize")
				req = httptest.NewRequest(http.MethodPost, "/auth/authorize", strings.NewReader(validAuthorizeQuery))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req = req.WithContext(settled.Context())
			}
			req = req.WithContext(reqctx.WithPageClient(req.Context(), &reqctx.PageClient{}))
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			require.Equal(t, http.StatusInternalServerError, rr.Code)
			head := readFormPostHead(t, rr.Body.String())
			assert.Equal(t, tc.wantDataTheme, head.dataTheme)
			assert.Equal(t, tc.wantDataTheme, head.colorScheme)
			if assert.Len(t, head.stylesheets, 2, "main.css, then the brand's stylesheet") {
				assert.Equal(t, tc.wantBrandHref, head.stylesheets[1])
			}
		})
	}
}

// The address check's own faults, with the real validator: a failed read of the client knows no
// client, so its 500 is drawn in the default brand, while a failed read of the client's redirect
// URIs comes after the client was read, so its 500 is drawn in that client's brand, on GET and on
// POST alike (#812).
func TestAuthorize_AnAddressCheckFaultKeepsTheBrandOnceItHasReadTheClient(t *testing.T) {
	night := &record.Brand{Id: 7, Name: "Night", Appearance: record.BrandAppearanceDark, Theme: "plum"}
	day := &record.Brand{Id: 12, Name: "Day", Appearance: record.BrandAppearanceLight, Theme: "avocado"}

	for _, tc := range []struct {
		name          string
		method        string
		clientRead    bool
		wantDataTheme string
		wantBrandHref string
	}{
		{name: "GET, the redirect URIs' read failing after the client's", method: http.MethodGet, clientRead: true,
			wantDataTheme: "light", wantBrandHref: brandStylesheetHrefForTest(t, 12, "avocado")},
		{name: "POST, the redirect URIs' read failing after the client's", method: http.MethodPost, clientRead: true,
			wantDataTheme: "light", wantBrandHref: brandStylesheetHrefForTest(t, 12, "avocado")},
		{name: "GET, the client's read failing", method: http.MethodGet, clientRead: false,
			wantDataTheme: "dark", wantBrandHref: brandStylesheetHrefForTest(t, 7, "plum")},
		{name: "POST, the client's read failing", method: http.MethodPost, clientRead: false,
			wantDataTheme: "dark", wantBrandHref: brandStylesheetHrefForTest(t, 7, "plum")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("GetDefaultBrand", mock.Anything, mock.Anything).Return(night, nil).Maybe()
			database.On("GetClientPageBrand", mock.Anything, mock.Anything, "test-client").Return(day, nil).Maybe()
			renderer := render.New(web.TemplateFS(), web.StaticFS(), database)

			if tc.clientRead {
				client := &record.Client{Id: 1, ClientIdentifier: "test-client", Enabled: true}
				database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
					Return(client, nil).Once()
				database.On("ClientLoadRedirectURIs", mock.Anything, mock.Anything, client).
					Return(errors.New("injected redirect URIs read fault")).Once()
			} else {
				database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
					Return(nil, errors.New("injected client read fault")).Once()
			}
			validator := protocolvalidation.NewAuthorizeValidator(database)

			var handler http.HandlerFunc
			var req *http.Request
			if tc.method == http.MethodGet {
				handler = buildAuthorizeGet(authorizeGetDeps{pageRenderer: renderer, database: database,
					authorizeValidator: validator})
				req = renderableRequest("/auth/authorize?" + validAuthorizeQuery)
			} else {
				handler = buildAuthorizePost(authorizePostDeps{pageRenderer: renderer, database: database,
					authorizeValidator: validator})
				settled := renderableRequest("/auth/authorize")
				req = httptest.NewRequest(http.MethodPost, "/auth/authorize", strings.NewReader(validAuthorizeQuery))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req = req.WithContext(settled.Context())
			}
			req = req.WithContext(reqctx.WithPageClient(req.Context(), &reqctx.PageClient{}))
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			require.Equal(t, http.StatusInternalServerError, rr.Code)
			head := readFormPostHead(t, rr.Body.String())
			assert.Equal(t, tc.wantDataTheme, head.dataTheme)
			assert.Equal(t, tc.wantDataTheme, head.colorScheme)
			if assert.Len(t, head.stylesheets, 2, "main.css, then the brand's stylesheet") {
				assert.Equal(t, tc.wantBrandHref, head.stylesheets[1])
			}
		})
	}
}
