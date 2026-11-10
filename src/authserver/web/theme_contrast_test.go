package web

import (
	"maps"
	"math"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/brandthemes"
)

// The two copies of ui.css, the auth server's and the admin console's. Each draws every page in
// two palettes: the light one from its @theme block, the dark one from the dark variant that
// overrides it. A test of the console's copy holds it to this one byte for byte (#617), and the
// test below holds both to the Blueberry preset (#810 decision 4).
const uiCSS = "tailwindcss/ui.css"

const consoleUICSS = "../../adminconsole/web/tailwindcss/ui.css"

var colorToken = regexp.MustCompile(`--color-([a-z-]+):\s*(#[0-9a-f]{6});`)

func themePalettes(t *testing.T, path string) (light, dark map[string]string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	css := string(b)

	themeAt := strings.Index(css, "@theme {")
	darkAt := strings.Index(css, "@variant dark {")
	if themeAt < 0 || darkAt < 0 {
		t.Fatalf("%s: no @theme block or no dark variant to read the palettes from", path)
	}
	block := func(from int) string {
		end := strings.Index(css[from:], "}")
		return css[from : from+end]
	}
	read := func(src string) map[string]string {
		m := map[string]string{}
		for _, match := range colorToken.FindAllStringSubmatch(src, -1) {
			m[match[1]] = match[2]
		}
		return m
	}
	light, dark = read(block(themeAt)), read(block(darkAt))
	if len(light) == 0 || len(dark) == 0 {
		t.Fatalf("%s: read %d light and %d dark color tokens", path, len(light), len(dark))
	}
	for name := range light {
		if _, ok := dark[name]; !ok {
			t.Errorf("%s: --color-%s has no dark value, so the dark theme draws it light", path, name)
		}
	}
	return light, dark
}

// luminance is the relative luminance of a #rrggbb color, per WCAG 2.2's definition.
func luminance(t *testing.T, hex string) float64 {
	t.Helper()
	channel := func(s string) float64 {
		v, err := strconv.ParseUint(s, 16, 8)
		if err != nil {
			t.Fatalf("%s is not a #rrggbb color", hex)
		}
		c := float64(v) / 255
		if c <= 0.04045 {
			return c / 12.92
		}
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	return 0.2126*channel(hex[1:3]) + 0.7152*channel(hex[3:5]) + 0.0722*channel(hex[5:7])
}

func contrast(t *testing.T, a, b string) float64 {
	la, lb := luminance(t, a), luminance(t, b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// Every pair of tokens a component draws text on, at WCAG 2.2 AA's 4.5:1 for normal text, and every
// pair a component draws a boundary or a focus ring on, at 3:1 for non-text contrast (1.4.11), in
// both modes of every built-in theme. High contrast holds its text to AAA's 7:1. A link is drawn in
// the main color on a hovered table row and inside note and caution notices, and in the strong
// shade when hovered there, so those six pairs are text pairs too (#810 decision 9). A palette edit
// that loses any of them cannot ship. Blueberry is the palette of ui.css, held to it below.
func TestThemeContrast_EveryPairMeetsWCAGAA(t *testing.T) {
	text := [][2]string{
		{"ink", "canvas"}, {"ink", "surface"}, {"ink", "subtle"}, {"ink", "brand-soft"},
		{"ink-muted", "canvas"}, {"ink-muted", "surface"}, {"ink-muted", "subtle"}, {"ink-muted", "brand-soft"},
		{"brand", "canvas"}, {"brand", "surface"}, {"brand-strong", "surface"},
		{"on-brand", "brand"}, {"on-brand", "brand-strong"},
		{"on-danger", "danger"}, {"on-danger", "danger-strong"},
		{"danger-ink", "canvas"}, {"danger-ink", "surface"}, {"danger-ink", "danger-soft"},
		{"positive-ink", "positive-soft"}, {"caution-ink", "caution-soft"}, {"note-ink", "note-soft"},
		{"ink-muted", "positive-soft"}, {"ink-muted", "caution-soft"},
		{"brand", "subtle"}, {"brand", "note-soft"}, {"brand", "caution-soft"},
		{"brand-strong", "subtle"}, {"brand-strong", "note-soft"}, {"brand-strong", "caution-soft"},
	}
	boundary := [][2]string{
		{"line-strong", "canvas"}, {"line-strong", "surface"},
		{"focus", "canvas"}, {"focus", "surface"}, {"focus", "subtle"},
		{"brand", "subtle"},
		{"danger", "surface"},
	}

	presets := brandthemes.All()
	var keys []string
	for _, preset := range presets {
		keys = append(keys, preset.Key)
	}
	want := []string{"blueberry", "blackberry", "avocado", "plum", "tangerine", "guava", "coconut", "high-contrast"}
	if !slices.Equal(keys, want) {
		t.Fatalf("the built-in themes are %v, want %v in this order", keys, want)
	}

	// Every theme sets each of the 23 tokens ui.css declares, so no token of one is left drawn in
	// another's colors.
	uiLight, _ := themePalettes(t, uiCSS)
	tokens := slices.Sorted(maps.Keys(uiLight))
	if len(tokens) != 23 {
		t.Fatalf("%s declares %d color tokens, want 23", uiCSS, len(tokens))
	}

	for _, preset := range presets {
		textLeast := 4.5
		if preset.Key == "high-contrast" {
			textLeast = 7
		}
		for mode, palette := range map[string]map[string]string{"light": preset.Light, "dark": preset.Dark} {
			if got := slices.Sorted(maps.Keys(palette)); !slices.Equal(got, tokens) {
				t.Errorf("%s %s: the palette sets %v, want %v", preset.Key, mode, got, tokens)
			}
			check := func(pairs [][2]string, least float64) {
				for _, p := range pairs {
					fg, bg := palette[p[0]], palette[p[1]]
					if fg == "" || bg == "" {
						t.Errorf("%s %s: no %s or no %s", preset.Key, mode, p[0], p[1])
						continue
					}
					if c := contrast(t, fg, bg); c < least {
						t.Errorf("%s %s: %s (%s) on %s (%s) is %.2f:1, below %.1f:1", preset.Key, mode, p[0], fg, p[1], bg, c, least)
					}
				}
			}
			check(text, textLeast)
			check(boundary, 3)
		}
	}
}

// Blueberry is the built-in theme both copies of ui.css draw, so a brand on it leaves every token
// to main.css and its stylesheet declares no colors (#810 decision 4). The preset still holds its 23
// values in both modes, which the contrast test above and the admin API's theme list read, so they
// must be the very values each ui.css holds: a palette edit to ui.css that misses the preset, or
// the reverse, fails here.
func TestThemeContrast_BlueberryIsBothCopiesOfUICSS(t *testing.T) {
	blueberry, ok := brandthemes.Get("blueberry")
	if !ok {
		t.Fatal("there is no blueberry theme")
	}
	for _, path := range []string{uiCSS, consoleUICSS} {
		light, dark := themePalettes(t, path)
		if !maps.Equal(light, map[string]string(blueberry.Light)) {
			t.Errorf("%s: the light palette is %v, and Blueberry's light is %v", path, light, blueberry.Light)
		}
		if !maps.Equal(dark, map[string]string(blueberry.Dark)) {
			t.Errorf("%s: the dark palette is %v, and Blueberry's dark is %v", path, dark, blueberry.Dark)
		}
	}
}
