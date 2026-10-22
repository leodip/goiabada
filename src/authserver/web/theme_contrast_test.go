package web

import (
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The two palettes ui.css draws every page in, read from the file itself: the light one from its
// @theme block, the dark one from the dark variant that overrides it. A test of the copy beside the
// admin console's input.css holds that copy to this one (#617).
const uiCSS = "tailwindcss/ui.css"

var colorToken = regexp.MustCompile(`--color-([a-z-]+):\s*(#[0-9a-f]{6});`)

func themePalettes(t *testing.T) (light, dark map[string]string) {
	t.Helper()
	b, err := os.ReadFile(uiCSS)
	if err != nil {
		t.Fatal(err)
	}
	css := string(b)

	themeAt := strings.Index(css, "@theme {")
	darkAt := strings.Index(css, "@variant dark {")
	if themeAt < 0 || darkAt < 0 {
		t.Fatalf("%s: no @theme block or no dark variant to read the palettes from", uiCSS)
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
		t.Fatalf("%s: read %d light and %d dark color tokens", uiCSS, len(light), len(dark))
	}
	for name := range light {
		if _, ok := dark[name]; !ok {
			t.Errorf("%s: --color-%s has no dark value, so the dark theme draws it light", uiCSS, name)
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
// both themes. A palette edit that loses either cannot ship.
func TestThemeContrast_EveryPairMeetsWCAGAA(t *testing.T) {
	light, dark := themePalettes(t)

	text := [][2]string{
		{"ink", "canvas"}, {"ink", "surface"}, {"ink", "subtle"}, {"ink", "brand-soft"},
		{"ink-muted", "canvas"}, {"ink-muted", "surface"}, {"ink-muted", "subtle"}, {"ink-muted", "brand-soft"},
		{"brand", "canvas"}, {"brand", "surface"}, {"brand-strong", "surface"},
		{"on-brand", "brand"}, {"on-brand", "brand-strong"},
		{"on-danger", "danger"}, {"on-danger", "danger-strong"},
		{"danger-ink", "canvas"}, {"danger-ink", "surface"}, {"danger-ink", "danger-soft"},
		{"positive-ink", "positive-soft"}, {"caution-ink", "caution-soft"}, {"note-ink", "note-soft"},
		{"ink-muted", "positive-soft"}, {"ink-muted", "caution-soft"},
	}
	boundary := [][2]string{
		{"line-strong", "canvas"}, {"line-strong", "surface"},
		{"focus", "canvas"}, {"focus", "surface"}, {"focus", "subtle"},
		{"brand", "subtle"},
		{"danger", "surface"},
	}

	for theme, palette := range map[string]map[string]string{"light": light, "dark": dark} {
		check := func(pairs [][2]string, least float64) {
			for _, p := range pairs {
				fg, bg := palette[p[0]], palette[p[1]]
				if fg == "" || bg == "" {
					t.Errorf("%s: no --color-%s or --color-%s in the %s palette", uiCSS, p[0], p[1], theme)
					continue
				}
				if c := contrast(t, fg, bg); c < least {
					t.Errorf("%s theme: %s (%s) on %s (%s) is %.2f:1, below %.1f:1", theme, p[0], fg, p[1], bg, c, least)
				}
			}
		}
		check(text, 4.5)
		check(boundary, 3)
	}
}
