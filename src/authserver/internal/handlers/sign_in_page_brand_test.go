package handlers

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/brandthemes"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/render"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/web"
)

// A step's pages are drawn in the brand of the client the request's sign-in is for, which the step
// middleware names before the step runs; the page saying a sign-in is no longer active is drawn in
// the default brand even then, since it acts on no sign-in. That is the page a step answers when its
// save finds the browser no longer holding its sign-in, after the sign-in was read and its client
// named (#812).
func TestCeremonyBoundary_TheNoLongerActivePageTakesNoClientsBrand(t *testing.T) {
	night := &record.Brand{Id: 7, Name: "Night", Appearance: record.BrandAppearanceDark, Theme: "plum"}
	day := &record.Brand{Id: 12, Name: "Day", Appearance: record.BrandAppearanceLight, Theme: "avocado"}

	for _, tc := range []struct {
		name          string
		answer        func(b *CeremonyBoundary, w http.ResponseWriter, r *http.Request)
		wantDataTheme string
		wantBrandHref string
	}{
		{
			name: "a step whose save found its sign-in replaced",
			answer: func(b *CeremonyBoundary, w http.ResponseWriter, r *http.Request) {
				b.answerStepSaveFailure(w, r, ceremony.ErrCeremonyReplaced)
			},
			wantDataTheme: "dark",
			wantBrandHref: brandStylesheetHrefForTest(t, 7, "plum"),
		},
		{
			name: "a step refusing a state the sign-in has passed",
			answer: func(b *CeremonyBoundary, w http.ResponseWriter, r *http.Request) {
				b.requireAuthState(w, r, &ceremony.AuthContext{AuthState: ceremony.AuthStateRequiresConsent},
					ceremony.AuthStateLevel1Password)
			},
			wantDataTheme: "light",
			wantBrandHref: brandStylesheetHrefForTest(t, 12, "avocado"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("GetDefaultBrand", mock.Anything, mock.Anything).Return(night, nil).Maybe()
			database.On("GetClientPageBrand", mock.Anything, mock.Anything, "app-1").Return(day, nil).Maybe()
			boundary := testCeremonyBoundary(render.New(web.TemplateFS(), web.StaticFS(), database), nil, nil)

			req := renderableRequest("/auth/pwd")
			req = req.WithContext(reqctx.WithPageClient(req.Context(), &reqctx.PageClient{}))
			reqctx.NamePageClient(req.Context(), "app-1")
			rr := httptest.NewRecorder()

			tc.answer(boundary, rr, req)

			require.Equal(t, http.StatusBadRequest, rr.Code)
			head := readFormPostHead(t, rr.Body.String())
			assert.Equal(t, tc.wantDataTheme, head.dataTheme)
			assert.Equal(t, tc.wantDataTheme, head.colorScheme)
			if assert.Len(t, head.stylesheets, 2, "main.css, then the brand's stylesheet") {
				assert.Equal(t, tc.wantBrandHref, head.stylesheets[1])
			}
		})
	}
}

// brandStylesheetHrefForTest is the link a page draws brand id on theme with: the brand's own
// stylesheet route, named by the fingerprint the built-in theme's stylesheet is served under.
func brandStylesheetHrefForTest(t *testing.T, id int64, theme string) string {
	t.Helper()
	stylesheet, ok := brandthemes.StylesheetOf(theme)
	require.True(t, ok, theme)
	return "/brand/" + strconv.FormatInt(id, 10) + "/stylesheet.css?v=" + stylesheet.Fingerprint
}
