package web

import (
	"maps"
	"math"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/brandthemes"
	"github.com/leodip/goiabada/core/palette"
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

// Every pair of the shared list (core/palette) meets its minimum in both modes of every built-in
// theme: WCAG 2.2 AA's 4.5:1 for a pair a component draws text in, and 3:1 for non-text contrast
// (1.4.11) for a boundary or a focus ring. High contrast holds its text pairs to AAA's 7:1 besides.
// A palette edit that loses any of them cannot ship. Blueberry is the palette of ui.css, held to it
// below.
func TestThemeContrast_EveryPairMeetsWCAGAA(t *testing.T) {
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
		for mode, colors := range map[string]map[string]string{"light": preset.Light, "dark": preset.Dark} {
			if got := slices.Sorted(maps.Keys(colors)); !slices.Equal(got, tokens) {
				t.Errorf("%s %s: the palette sets %v, want %v", preset.Key, mode, got, tokens)
			}
			failures, err := palette.Check(colors)
			if err != nil {
				t.Errorf("%s %s: %v", preset.Key, mode, err)
				continue
			}
			for _, f := range failures {
				t.Errorf("%s %s: %s (%s) on %s (%s) is %.2f:1, below %.1f:1", preset.Key, mode,
					f.Foreground, colors[f.Foreground], f.Background, colors[f.Background], f.Ratio, f.Minimum)
			}
			if preset.Key != "high-contrast" {
				continue
			}
			for _, p := range palette.Pairs() {
				if p.Minimum != palette.TextMinimum {
					continue
				}
				fg, bg := colors[p.Foreground], colors[p.Background]
				c, err := palette.ContrastRatio(fg, bg)
				if err != nil {
					t.Errorf("%s %s: %v", preset.Key, mode, err)
				} else if c < 7 {
					t.Errorf("%s %s: %s (%s) on %s (%s) is %.2f:1, below 7:1", preset.Key, mode, p.Foreground, fg, p.Background, bg, c)
				}
			}
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

// A basic palette's colors are worked out from four (#815 decision 4). Each built-in theme but High
// contrast, rebuilt that way from its own background, card, text and brand color in each mode, has no
// failing pair, and every color worked out is within 0.05 in OKLab of the theme's hand-made one,
// where 0.02 is barely visible. The status colors are Blueberry's, which the six other themes share.
func TestThemeContrast_BasicPaletteRebuildsTheBuiltInThemes(t *testing.T) {
	for _, preset := range brandthemes.All() {
		if preset.Key == "high-contrast" {
			continue
		}
		for mode, handMade := range map[string]map[string]string{"light": preset.Light, "dark": preset.Dark} {
			got, err := palette.Derive(map[string]string{
				"canvas": handMade["canvas"], "surface": handMade["surface"], "ink": handMade["ink"], "brand": handMade["brand"],
			})
			if err != nil {
				t.Errorf("%s %s: %v", preset.Key, mode, err)
				continue
			}
			failures, err := palette.Check(got)
			if err != nil {
				t.Errorf("%s %s: %v", preset.Key, mode, err)
				continue
			}
			for _, f := range failures {
				t.Errorf("%s %s rebuilt: %s (%s) on %s (%s) is %.2f:1, below %.1f:1", preset.Key, mode,
					f.Foreground, got[f.Foreground], f.Background, got[f.Background], f.Ratio, f.Minimum)
			}
			for _, token := range slices.Sorted(maps.Keys(handMade)) {
				if d := oklabDistance(t, got[token], handMade[token]); d > 0.05 {
					t.Errorf("%s %s rebuilt: %s is %s, %.3f in OKLab from the hand-made %s", preset.Key, mode, token, got[token], d, handMade[token])
				}
			}
		}
	}
}

// A basic palette takes Blueberry's eleven status colors (#815 decision 13), which core/palette
// declares, since core cannot read the auth server's themes: they are held here to the Blueberry
// theme itself, the light set for a mode whose text is darker than its card and the dark set
// otherwise, whichever column the colors are typed in.
func TestThemeContrast_BasicPaletteStatusColorsAreBlueberrys(t *testing.T) {
	blueberry, ok := brandthemes.Get("blueberry")
	if !ok {
		t.Fatal("there is no blueberry theme")
	}
	status := []string{"danger", "danger-strong", "on-danger", "danger-soft", "danger-ink", "positive-soft",
		"positive-ink", "caution-soft", "caution-ink", "note-soft", "note-ink"}
	for _, tc := range []struct {
		what    string
		entered map[string]string
		want    brandthemes.Palette
	}{
		{"Blueberry's light colors", map[string]string{"canvas": "#f4f5f7", "surface": "#ffffff", "ink": "#1a1f29", "brand": "#2456c4"}, blueberry.Light},
		{"Blueberry's dark colors", map[string]string{"canvas": "#0f1217", "surface": "#171b22", "ink": "#e6e8ec", "brand": "#8ab4ff"}, blueberry.Dark},
		{"a dark design, typed in the Light column", map[string]string{"canvas": "#101418", "surface": "#1a2026", "ink": "#eef2f5", "brand": "#6cb6ff"}, blueberry.Dark},
		{"white text on a navy card", map[string]string{"canvas": "#eef1f6", "surface": "#1f3a68", "ink": "#ffffff", "brand": "#ffd166"}, blueberry.Dark},
	} {
		got, err := palette.Derive(tc.entered)
		if err != nil {
			t.Fatalf("%s: %v", tc.what, err)
		}
		for _, token := range status {
			if got[token] != tc.want[token] {
				t.Errorf("%s: %s is %s, and Blueberry's is %s", tc.what, token, got[token], tc.want[token])
			}
		}
	}
}

// oklabDistance is the Euclidean distance of two colors in OKLab.
func oklabDistance(t *testing.T, x, y string) float64 {
	t.Helper()
	a, err := palette.ToOKLCH(x)
	if err != nil {
		t.Fatal(err)
	}
	b, err := palette.ToOKLCH(y)
	if err != nil {
		t.Fatal(err)
	}
	ha, hb := a.H*math.Pi/180, b.H*math.Pi/180
	return math.Hypot(a.L-b.L, math.Hypot(a.C*math.Cos(ha)-b.C*math.Cos(hb), a.C*math.Sin(ha)-b.C*math.Sin(hb)))
}
