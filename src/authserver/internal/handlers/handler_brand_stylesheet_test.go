package handlers

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/brandthemes"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// avocadoStylesheet is the stylesheet of a brand on Avocado, written out by hand from the values
// approved for #810: Avocado's twelve tokens with Blueberry's eleven status tokens, the light
// palette on the root, and the dark one under the two conditions ui.css's dark variant applies it
// on.
const avocadoStylesheet = `:root {
  --color-canvas: #f3f6f4;
  --color-surface: #ffffff;
  --color-subtle: #ebf0ed;
  --color-line: #d5ddd8;
  --color-line-strong: #6c7b72;
  --color-ink: #18211c;
  --color-ink-muted: #4d5c53;
  --color-brand: #1f6b43;
  --color-brand-strong: #175233;
  --color-on-brand: #ffffff;
  --color-brand-soft: #e0f0e6;
  --color-danger: #b42318;
  --color-danger-strong: #8f1c13;
  --color-on-danger: #ffffff;
  --color-danger-soft: #fdeceb;
  --color-danger-ink: #8f1c13;
  --color-positive-soft: #e3f3e8;
  --color-positive-ink: #17612f;
  --color-caution-soft: #fdf2d6;
  --color-caution-ink: #6b4400;
  --color-note-soft: #e6edfb;
  --color-note-ink: #1d4796;
  --color-focus: #1f6b43;
}

@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --color-canvas: #0e1411;
    --color-surface: #151c18;
    --color-subtle: #1c2520;
    --color-line: #2c3831;
    --color-line-strong: #6b7c72;
    --color-ink: #e4e9e6;
    --color-ink-muted: #9daba3;
    --color-brand: #7fd3a0;
    --color-brand-strong: #a5e3bd;
    --color-on-brand: #0a2616;
    --color-brand-soft: #173224;
    --color-danger: #ff8f85;
    --color-danger-strong: #ffb0a8;
    --color-on-danger: #330b07;
    --color-danger-soft: #3a1714;
    --color-danger-ink: #ffb4ab;
    --color-positive-soft: #11291a;
    --color-positive-ink: #8fd6a5;
    --color-caution-soft: #2e2410;
    --color-caution-ink: #f0c96a;
    --color-note-soft: #142340;
    --color-note-ink: #a8c7ff;
    --color-focus: #7fd3a0;
  }
}

:root[data-theme="dark"] {
  --color-canvas: #0e1411;
  --color-surface: #151c18;
  --color-subtle: #1c2520;
  --color-line: #2c3831;
  --color-line-strong: #6b7c72;
  --color-ink: #e4e9e6;
  --color-ink-muted: #9daba3;
  --color-brand: #7fd3a0;
  --color-brand-strong: #a5e3bd;
  --color-on-brand: #0a2616;
  --color-brand-soft: #173224;
  --color-danger: #ff8f85;
  --color-danger-strong: #ffb0a8;
  --color-on-danger: #330b07;
  --color-danger-soft: #3a1714;
  --color-danger-ink: #ffb4ab;
  --color-positive-soft: #11291a;
  --color-positive-ink: #8fd6a5;
  --color-caution-soft: #2e2410;
  --color-caution-ink: #f0c96a;
  --color-note-soft: #142340;
  --color-note-ink: #a8c7ff;
  --color-focus: #7fd3a0;
}
`

const (
	yearCache       = "public, max-age=31536000, immutable"
	fiveMinuteCache = "public, max-age=300"
)

// themedBrand is a brand on theme with the kit migration 000091 gives an existing brand, rounded and
// on System UI, which draws as a brand did before the kit.
func themedBrand(id int64, theme string) *record.Brand {
	brand := record.NewBrand("Shop", record.BrandAppearanceAuto, theme)
	brand.Id = id
	return &brand
}

// kitBrand is the brand of id 7 on theme with the given corners and font.
func kitBrand(theme string, corners record.BrandCorners, font record.BrandFont) *record.Brand {
	brand := themedBrand(7, theme)
	brand.Corners, brand.Font = corners, font
	return brand
}

// brandStylesheetPath is a brand's stylesheet path as the pages link it, fingerprint included.
func brandStylesheetPath(t *testing.T, brandId int64, theme string) string {
	t.Helper()
	path, err := brandthemes.StylesheetPath(themedBrand(brandId, theme))
	require.NoError(t, err)
	return path
}

// getBrandStylesheet requests target from the full stylesheet's handler, the brand of id 7 being
// brand, or none when brand is nil.
func getBrandStylesheet(t *testing.T, target string, brand *record.Brand) *httptest.ResponseRecorder {
	t.Helper()
	return getStylesheetFrom(t, HandleBrandStylesheetGet, target, brand)
}

// getColorsStylesheet requests target from the colors-only stylesheet's handler, as
// getBrandStylesheet does from the full one's.
func getColorsStylesheet(t *testing.T, target string, brand *record.Brand) *httptest.ResponseRecorder {
	t.Helper()
	return getStylesheetFrom(t, HandleBrandColorsStylesheetGet, target, brand)
}

func getStylesheetFrom(t *testing.T, handler func(PageRenderer, brandStylesheetDatabase) http.HandlerFunc,
	target string, brand *record.Brand) *httptest.ResponseRecorder {
	t.Helper()
	database := datamocks.NewDatabase(t)
	database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(brand, nil).Once()

	req := withPathValue(httptest.NewRequest(http.MethodGet, target, nil), "id", "7")
	rr := httptest.NewRecorder()
	handler(handlersmocks.NewPageRenderer(t), database).ServeHTTP(rr, req)
	return rr
}

// A brand on any theme but Blueberry is drawn in that theme's 23 colors, light and dark, under the
// selectors ui.css's dark variant uses, and the URL the pages link it by is cacheable for a year.
func TestHandleBrandStylesheetGet_DeclaresTheThemesColorsInBothModes(t *testing.T) {
	brand := themedBrand(7, "avocado")

	rr := getBrandStylesheet(t, brandStylesheetPath(t, 7, "avocado"), brand)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "text/css; charset=utf-8", rr.Header().Get("Content-Type"))
	assert.Equal(t, yearCache, rr.Header().Get("Cache-Control"))
	assert.Equal(t, avocadoStylesheet, rr.Body.String())
}

// Blueberry is the palette main.css is built with, so its stylesheet declares no colors and an
// operator's regenerated colors stay (#810 decision 4). It is still served and still linked.
func TestHandleBrandStylesheetGet_BlueberryDeclaresNoColors(t *testing.T) {
	brand := themedBrand(7, "blueberry")
	brand.Appearance = record.BrandAppearanceDark

	rr := getBrandStylesheet(t, brandStylesheetPath(t, 7, "blueberry"), brand)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "text/css; charset=utf-8", rr.Header().Get("Content-Type"))
	assert.Equal(t, yearCache, rr.Header().Get("Cache-Control"))
	body := rr.Body.String()
	assert.NotContains(t, body, "--color-")
	assert.NotContains(t, body, "{", "a Blueberry stylesheet has no rule at all")
}

// The fingerprint names the stylesheet's contents, the first twelve hex digits of their SHA-256 as
// a static file's are, so a release that changes a theme's colors changes the URL its pages link.
// Another theme's stylesheet has another one, and the brand's id is in the path.
func TestBrandStylesheetPath_NamesTheBrandAndTheContents(t *testing.T) {
	avocado := brandStylesheetPath(t, 7, "avocado")
	digest := sha256.Sum256([]byte(avocadoStylesheet))
	assert.Equal(t, "/brand/7/stylesheet.css?v="+hex.EncodeToString(digest[:])[:12], avocado)
	assert.NotEqual(t, avocado, brandStylesheetPath(t, 7, "plum"))
	assert.Equal(t, strings.Replace(avocado, "/brand/7/", "/brand/8/", 1), brandStylesheetPath(t, 8, "avocado"))

	_, err := brandthemes.StylesheetPath(themedBrand(7, "lime"))
	assert.Error(t, err, "lime is no built-in theme")
}

// Only the fingerprint of the stylesheet as it is now gets the year (#810 decision 7). A stale
// one, as a page cached before the brand's theme changed links, a malformed one and none get the
// current stylesheet with five minutes, so a browser never keeps an old stylesheet for a year
// under a URL that names it.
func TestHandleBrandStylesheetGet_OnlyTheCurrentFingerprintIsCachedForAYear(t *testing.T) {
	current := brandStylesheetPath(t, 7, "avocado")
	stale := brandStylesheetPath(t, 7, "plum")
	_, currentFingerprint, _ := strings.Cut(current, "?v=")

	tests := []struct {
		name   string
		target string
		want   string
	}{
		{"current", current, yearCache},
		{"stale", stale, fiveMinuteCache},
		{"malformed", "/brand/7/stylesheet.css?v=not-a-fingerprint", fiveMinuteCache},
		{"upper case", "/brand/7/stylesheet.css?v=" + strings.ToUpper(currentFingerprint), fiveMinuteCache},
		{"empty", "/brand/7/stylesheet.css?v=", fiveMinuteCache},
		{"none", "/brand/7/stylesheet.css", fiveMinuteCache},
		{"twice", current + "&v=" + currentFingerprint, fiveMinuteCache},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := getBrandStylesheet(t, tt.target, themedBrand(7, "avocado"))

			require.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, tt.want, rr.Header().Get("Cache-Control"))
			assert.Equal(t, avocadoStylesheet, rr.Body.String(), "every request gets the current stylesheet")
		})
	}
}

// A brand that does not exist has no stylesheet, as a static file that does not exist has none.
func TestHandleBrandStylesheetGet_UnknownBrandIsNotFound(t *testing.T) {
	rr := getBrandStylesheet(t, "/brand/7/stylesheet.css", nil)

	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.NotEqual(t, yearCache, rr.Header().Get("Cache-Control"))
}

// An id that names no brand at all is not looked up.
func TestHandleBrandStylesheetGet_MalformedIdIsNotFound(t *testing.T) {
	for _, id := range []string{"", "abc", "-1", "0", "7x", "99999999999999999999"} {
		t.Run(id, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			req := withPathValue(httptest.NewRequest(http.MethodGet, "/brand/x/stylesheet.css", nil), "id", id)
			rr := httptest.NewRecorder()

			HandleBrandStylesheetGet(handlersmocks.NewPageRenderer(t), database).ServeHTTP(rr, req)

			assert.Equal(t, http.StatusNotFound, rr.Code)
		})
	}
}

// A brand that cannot be read is a server fault, answered as every file route answers one, and so
// is a stored theme that is none of the built-in ones, which no save writes.
func TestHandleBrandStylesheetGet_FaultsAreServerErrors(t *testing.T) {
	t.Run("database", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(nil, errors.New("connection refused")).Once()
		pageRenderer := handlersmocks.NewPageRenderer(t)
		pageRenderer.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "connection refused")
		})).Once()

		req := withPathValue(httptest.NewRequest(http.MethodGet, "/brand/7/stylesheet.css", nil), "id", "7")
		HandleBrandStylesheetGet(pageRenderer, database).ServeHTTP(httptest.NewRecorder(), req)
	})
	t.Run("unknown theme", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(7)).
			Return(&record.Brand{Id: 7, Name: "Shop", Appearance: record.BrandAppearanceAuto, Theme: "lime"}, nil).Once()
		pageRenderer := handlersmocks.NewPageRenderer(t)
		pageRenderer.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "lime")
		})).Once()

		req := withPathValue(httptest.NewRequest(http.MethodGet, "/brand/7/stylesheet.css", nil), "id", "7")
		HandleBrandStylesheetGet(pageRenderer, database).ServeHTTP(httptest.NewRecorder(), req)
	})
}

// The full stylesheet draws a brand's corners after its colors, by the two radius tokens ui.css
// declares (#813): square rounds nothing, and pill rounds a single-line control fully and the card
// and other panels to 1.5rem. Rounded is today's two radii, main.css's, so it declares none.
func TestHandleBrandStylesheetGet_DrawsEachCornerShape(t *testing.T) {
	for _, tc := range []struct {
		corners record.BrandCorners
		want    string
	}{
		{"square", avocadoStylesheet + "\n:root {\n  --radius-control: 0;\n  --radius-panel: 0;\n}\n"},
		{"rounded", avocadoStylesheet},
		{"pill", avocadoStylesheet + "\n:root {\n  --radius-control: 9999px;\n  --radius-panel: 1.5rem;\n}\n"},
	} {
		t.Run(string(tc.corners), func(t *testing.T) {
			brand := kitBrand("avocado", tc.corners, "system-ui")
			path, err := brandthemes.StylesheetPath(brand)
			require.NoError(t, err)

			rr := getBrandStylesheet(t, path, brand)

			require.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, yearCache, rr.Header().Get("Cache-Control"))
			assert.Equal(t, tc.want, rr.Body.String())
		})
	}
}

// The full stylesheet draws a brand's system family as the font every text but monospace takes,
// each a list of fonts a visitor's device already has (#813 decision 7). System UI is today's,
// main.css's, so it declares none, and so does the uploaded font while it has no file to draw.
func TestHandleBrandStylesheetGet_DrawsEachSystemFamily(t *testing.T) {
	for _, tc := range []struct {
		font  record.BrandFont
		stack string
	}{
		{"system-ui", ""},
		{"humanist", "Seravek, 'Gill Sans Nova', Ubuntu, Calibri, 'DejaVu Sans', source-sans-pro, sans-serif"},
		{"geometric", "Avenir, Montserrat, Corbel, 'URW Gothic', source-sans-pro, sans-serif"},
		{"serif", "Charter, 'Bitstream Charter', 'Sitka Text', Cambria, serif"},
		{"neo-grotesque", "Inter, Roboto, 'Helvetica Neue', 'Arial Nova', 'Nimbus Sans', Arial, sans-serif"},
		{"rounded", "ui-rounded, 'Hiragino Maru Gothic ProN', Quicksand, Comfortaa, Manjari, 'Arial Rounded MT', 'Arial Rounded MT Bold', Calibri, source-sans-pro, sans-serif"},
		{"uploaded", ""},
	} {
		t.Run(string(tc.font), func(t *testing.T) {
			brand := kitBrand("avocado", "rounded", tc.font)
			path, err := brandthemes.StylesheetPath(brand)
			require.NoError(t, err)

			rr := getBrandStylesheet(t, path, brand)

			require.Equal(t, http.StatusOK, rr.Code)
			want := avocadoStylesheet
			if tc.stack != "" {
				want += "\n:root {\n  --font-sans: " + tc.stack + ";\n}\n"
			}
			assert.Equal(t, want, rr.Body.String())
			assert.NotContains(t, rr.Body.String(), "--font-mono", "monospace text keeps its own font")
		})
	}
}

// Corners and a family together are one rule, the corners first. On Blueberry, whose colors are
// main.css's, the kit follows the note that the stylesheet declares no colors.
func TestHandleBrandStylesheetGet_DrawsTheCornersAndTheFamilyTogether(t *testing.T) {
	brand := kitBrand("blueberry", "pill", "serif")
	path, err := brandthemes.StylesheetPath(brand)
	require.NoError(t, err)

	rr := getBrandStylesheet(t, path, brand)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "/* Blueberry is the palette main.css is built with: this stylesheet declares no colors. */\n"+
		"\n"+
		":root {\n"+
		"  --radius-control: 9999px;\n"+
		"  --radius-panel: 1.5rem;\n"+
		"  --font-sans: Charter, 'Bitstream Charter', 'Sitka Text', Cambria, serif;\n"+
		"}\n", rr.Body.String())
}

// A brand nobody has changed is drawn exactly as today: Blueberry, rounded, on System UI, its full
// stylesheet declares nothing at all.
func TestHandleBrandStylesheetGet_ABrandNobodyChangedDeclaresNothing(t *testing.T) {
	brand := kitBrand("blueberry", "rounded", "system-ui")
	path, err := brandthemes.StylesheetPath(brand)
	require.NoError(t, err)

	rr := getBrandStylesheet(t, path, brand)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.NotContains(t, rr.Body.String(), "{")
}

// The colors-only stylesheet sets a brand's colors and nothing of its kit, whatever the kit holds,
// so an admin page that links it never receives the corners or the font (#813 decision 9).
func TestHandleBrandColorsStylesheetGet_SetsTheColorsAlone(t *testing.T) {
	for _, brand := range []*record.Brand{
		kitBrand("avocado", "rounded", "system-ui"),
		kitBrand("avocado", "square", "humanist"),
		kitBrand("avocado", "pill", "serif"),
		kitBrand("avocado", "pill", "uploaded"),
	} {
		t.Run(string(brand.Corners)+" "+string(brand.Font), func(t *testing.T) {
			path, err := brandthemes.ColorsStylesheetPath(brand)
			require.NoError(t, err)

			rr := getColorsStylesheet(t, path, brand)

			require.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, "text/css; charset=utf-8", rr.Header().Get("Content-Type"))
			assert.Equal(t, yearCache, rr.Header().Get("Cache-Control"))
			assert.Equal(t, avocadoStylesheet, rr.Body.String())
		})
	}
}

// Each stylesheet is linked by its own route and the fingerprint of its own contents: the
// colors-only one at /brand/{id}/colors.css, unchanged by the kit, and the full one at
// /brand/{id}/stylesheet.css, changed by each corner shape and family.
func TestBrandStylesheetPaths_NameEachStylesheetsContents(t *testing.T) {
	avocadoDigest := sha256.Sum256([]byte(avocadoStylesheet))
	avocadoFingerprint := hex.EncodeToString(avocadoDigest[:])[:12]
	pillSerif := kitBrand("avocado", "pill", "serif")

	colors, err := brandthemes.ColorsStylesheetPath(pillSerif)
	require.NoError(t, err)
	assert.Equal(t, "/brand/7/colors.css?v="+avocadoFingerprint, colors)

	full, err := brandthemes.StylesheetPath(pillSerif)
	require.NoError(t, err)
	fullDigest := sha256.Sum256([]byte(avocadoStylesheet + "\n:root {\n  --radius-control: 9999px;\n  --radius-panel: 1.5rem;\n" +
		"  --font-sans: Charter, 'Bitstream Charter', 'Sitka Text', Cambria, serif;\n}\n"))
	assert.Equal(t, "/brand/7/stylesheet.css?v="+hex.EncodeToString(fullDigest[:])[:12], full)

	seen := map[string]string{}
	for _, corners := range []record.BrandCorners{"square", "rounded", "pill"} {
		for _, font := range []record.BrandFont{"system-ui", "humanist", "geometric", "serif", "neo-grotesque", "rounded"} {
			brand := kitBrand("avocado", corners, font)
			path, pathErr := brandthemes.StylesheetPath(brand)
			require.NoError(t, pathErr)
			kit := string(corners) + " " + string(font)
			if other, ok := seen[path]; ok {
				t.Errorf("%s and %s are linked by one path, %s", other, kit, path)
			}
			seen[path] = kit
			colorsPath, pathErr := brandthemes.ColorsStylesheetPath(brand)
			require.NoError(t, pathErr)
			assert.Equal(t, colors, colorsPath, "the kit leaves the colors-only path as it is")
		}
	}

	_, err = brandthemes.ColorsStylesheetPath(themedBrand(7, "lime"))
	assert.Error(t, err, "lime is no built-in theme")
}

// Each stylesheet is kept for a year only by the fingerprint of its own contents: the full one's
// fingerprint names another stylesheet at the colors-only route, which is answered with five
// minutes, and the other way round.
func TestBrandStylesheets_OnlyTheirOwnCurrentFingerprintIsCachedForAYear(t *testing.T) {
	brand := kitBrand("avocado", "pill", "serif")
	full, err := brandthemes.StylesheetPath(brand)
	require.NoError(t, err)
	colors, err := brandthemes.ColorsStylesheetPath(brand)
	require.NoError(t, err)
	_, fullFingerprint, _ := strings.Cut(full, "?v=")
	_, colorsFingerprint, _ := strings.Cut(colors, "?v=")
	require.NotEqual(t, fullFingerprint, colorsFingerprint)

	assert.Equal(t, yearCache, getColorsStylesheet(t, colors, brand).Header().Get("Cache-Control"))
	assert.Equal(t, fiveMinuteCache, getColorsStylesheet(t, "/brand/7/colors.css?v="+fullFingerprint, brand).Header().Get("Cache-Control"))
	assert.Equal(t, fiveMinuteCache, getColorsStylesheet(t, "/brand/7/colors.css", brand).Header().Get("Cache-Control"))
	assert.Equal(t, yearCache, getBrandStylesheet(t, full, brand).Header().Get("Cache-Control"))
	assert.Equal(t, fiveMinuteCache, getBrandStylesheet(t, "/brand/7/stylesheet.css?v="+colorsFingerprint, brand).Header().Get("Cache-Control"))
}

// The colors-only route answers an unknown brand, a malformed id and a fault as the full one does.
func TestHandleBrandColorsStylesheetGet_AnswersFaultsAsTheFullOneDoes(t *testing.T) {
	assert.Equal(t, http.StatusNotFound, getColorsStylesheet(t, "/brand/7/colors.css", nil).Code)

	database := datamocks.NewDatabase(t)
	req := withPathValue(httptest.NewRequest(http.MethodGet, "/brand/x/colors.css", nil), "id", "x")
	rr := httptest.NewRecorder()
	HandleBrandColorsStylesheetGet(handlersmocks.NewPageRenderer(t), database).ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)

	database = datamocks.NewDatabase(t)
	database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(themedBrand(7, "lime"), nil).Once()
	pageRenderer := handlersmocks.NewPageRenderer(t)
	pageRenderer.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		return strings.Contains(err.Error(), "lime")
	})).Once()
	req = withPathValue(httptest.NewRequest(http.MethodGet, "/brand/7/colors.css", nil), "id", "7")
	HandleBrandColorsStylesheetGet(pageRenderer, database).ServeHTTP(httptest.NewRecorder(), req)
}
