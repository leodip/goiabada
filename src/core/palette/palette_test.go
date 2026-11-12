package palette

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The shared pair list holds each pair once, at its strictest minimum (#815 decision 5): 29 text
// pairs at 4.5:1 and 6 boundary and focus-ring pairs at 3:1, 35 in all. The brand color on the subtle
// background, which the built-in themes' test once listed among both, is a text pair.
func TestPairs(t *testing.T) {
	want := []Pair{
		{"ink", "canvas", 4.5}, {"ink", "surface", 4.5}, {"ink", "subtle", 4.5}, {"ink", "brand-soft", 4.5},
		{"ink-muted", "canvas", 4.5}, {"ink-muted", "surface", 4.5}, {"ink-muted", "subtle", 4.5}, {"ink-muted", "brand-soft", 4.5},
		{"brand", "canvas", 4.5}, {"brand", "surface", 4.5}, {"brand-strong", "surface", 4.5},
		{"on-brand", "brand", 4.5}, {"on-brand", "brand-strong", 4.5},
		{"on-danger", "danger", 4.5}, {"on-danger", "danger-strong", 4.5},
		{"danger-ink", "canvas", 4.5}, {"danger-ink", "surface", 4.5}, {"danger-ink", "danger-soft", 4.5},
		{"positive-ink", "positive-soft", 4.5}, {"caution-ink", "caution-soft", 4.5}, {"note-ink", "note-soft", 4.5},
		{"ink-muted", "positive-soft", 4.5}, {"ink-muted", "caution-soft", 4.5},
		{"brand", "subtle", 4.5}, {"brand", "note-soft", 4.5}, {"brand", "caution-soft", 4.5},
		{"brand-strong", "subtle", 4.5}, {"brand-strong", "note-soft", 4.5}, {"brand-strong", "caution-soft", 4.5},
		{"line-strong", "canvas", 3}, {"line-strong", "surface", 3},
		{"focus", "canvas", 3}, {"focus", "surface", 3}, {"focus", "subtle", 3},
		{"danger", "surface", 3},
	}
	pairs := Pairs()
	assert.Equal(t, want, pairs)
	require.Len(t, pairs, 35)

	seen := map[[2]string]bool{}
	for _, p := range pairs {
		key := [2]string{p.Foreground, p.Background}
		assert.False(t, seen[key], "%s on %s is listed twice", p.Foreground, p.Background)
		seen[key] = true
	}

	// A caller that changes its copy changes no other caller's list.
	pairs[0].Minimum = 1
	assert.Equal(t, want, Pairs())
}

func TestIsColor(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"#000000", true},
		{"#ffffff", true},
		{"#2456c4", true},
		{"#2456C4", true},
		{"#AbCdEf", true},
		{"", false},
		{"#", false},
		{"#fff", false},
		{"#fffffff", false},
		{"#ffffffff", false},
		{"ffffff", false},
		{"white", false},
		{"#gggggg", false},
		{"#12345z", false},
		{" #ffffff", false},
		{"#ffffff ", false},
		{"#ffffff\n", false},
		{"rgb(0,0,0)", false},
		{"+#fffff", false},
		{"#-12345", false},
		{"#0x1234", false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			assert.Equal(t, tc.want, IsColor(tc.value))
		})
	}
}

// Values from WCAG 2.2's definition of the contrast ratio, (L1 + 0.05) / (L2 + 0.05), and the
// gray steps it is commonly measured on: #767676 is the lightest gray that reaches 4.5:1 on white,
// and #949494 the lightest that reaches 3:1.
func TestContrastRatio(t *testing.T) {
	for _, tc := range []struct {
		foreground, background string
		atLeast, below         float64
	}{
		{"#000000", "#ffffff", 21, 21.000001},
		{"#ffffff", "#000000", 21, 21.000001},
		{"#ffffff", "#ffffff", 1, 1.000001},
		{"#767676", "#ffffff", 4.5, 4.55},
		{"#777777", "#ffffff", 4.47, 4.48},
		{"#949494", "#ffffff", 3, 3.04},
		{"#959595", "#ffffff", 2.99, 3},
		{"#FFFFFF", "#767676", 4.5, 4.55},
		// Pure red on white: luminance 0.2126, so 1.05 / 0.2626.
		{"#ff0000", "#ffffff", 3.998, 3.999},
	} {
		t.Run(tc.foreground+" on "+tc.background, func(t *testing.T) {
			ratio, err := ContrastRatio(tc.foreground, tc.background)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, ratio, tc.atLeast)
			assert.Less(t, ratio, tc.below)
		})
	}
}

func TestContrastRatio_RefusesAValueThatIsNotAColor(t *testing.T) {
	for _, pair := range [][2]string{{"#fff", "#ffffff"}, {"#ffffff", "white"}, {"", "#000000"}} {
		_, err := ContrastRatio(pair[0], pair[1])
		assert.Error(t, err, "%q on %q", pair[0], pair[1])
	}
}

// blueberryLight is Blueberry's light palette, which passes every pair.
func blueberryLight() map[string]string {
	return map[string]string{
		"canvas": "#f4f5f7", "surface": "#ffffff", "subtle": "#eef0f3", "line": "#d8dce3",
		"line-strong": "#737d8c", "ink": "#1a1f29", "ink-muted": "#535c6c", "brand": "#2456c4",
		"brand-strong": "#1c4399", "on-brand": "#ffffff", "brand-soft": "#e6edfb", "danger": "#b42318",
		"danger-strong": "#8f1c13", "on-danger": "#ffffff", "danger-soft": "#fdeceb", "danger-ink": "#8f1c13",
		"positive-soft": "#e3f3e8", "positive-ink": "#17612f", "caution-soft": "#fdf2d6", "caution-ink": "#6b4400",
		"note-soft": "#e6edfb", "note-ink": "#1d4796", "focus": "#2456c4",
	}
}

func TestCheck_APassingPaletteHasNoFailingPair(t *testing.T) {
	failures, err := Check(blueberryLight())
	require.NoError(t, err)
	assert.Empty(t, failures)
	assert.NotNil(t, failures, "no failing pair is an empty list, which the admin API answers as []")
}

// A failing pair is decided on the exact ratio and reported cut to two decimals, never rounded up
// (#815 decision 5): #777777 on white is 4.478:1, which reads 4.47.
func TestCheck_ListsEachFailingPairInTheListsOrder(t *testing.T) {
	colors := blueberryLight()
	colors["ink-muted"] = "#777777" // 4.478:1 on white, the surface
	colors["surface"] = "#FFFFFF"   // either case is a color
	colors["focus"] = "#959595"     // 2.99:1 on white, and lower on the canvas and the subtle background

	failures, err := Check(colors)
	require.NoError(t, err)

	var got []Failure
	for _, f := range failures {
		if f.Background == "surface" {
			got = append(got, f)
		}
	}
	assert.Equal(t, []Failure{
		{Foreground: "ink-muted", Background: "surface", Ratio: 4.47, Minimum: 4.5},
		{Foreground: "focus", Background: "surface", Ratio: 2.99, Minimum: 3},
	}, got)

	// Every failing pair, in the shared list's order: muted text on every background lighter than
	// it, then the focus ring on the canvas, the surface and the subtle background.
	var names [][2]string
	for _, f := range failures {
		names = append(names, [2]string{f.Foreground, f.Background})
		assert.Less(t, f.Ratio, f.Minimum)
	}
	assert.Equal(t, [][2]string{
		{"ink-muted", "canvas"}, {"ink-muted", "surface"}, {"ink-muted", "subtle"}, {"ink-muted", "brand-soft"},
		{"ink-muted", "positive-soft"}, {"ink-muted", "caution-soft"},
		{"focus", "canvas"}, {"focus", "surface"}, {"focus", "subtle"},
	}, names)
}

// The minimum a pair is held to is its own: the brand color on the subtle background is a text
// pair, so a brand color between 3:1 and 4.5:1 on it fails.
func TestCheck_TheBrandColorOnTheSubtleBackgroundIsHeldTo4_5(t *testing.T) {
	colors := blueberryLight()
	colors["subtle"] = "#ffffff"
	colors["brand"] = "#ff0000" // 3.99:1 on white
	failures, err := Check(colors)
	require.NoError(t, err)
	assert.Contains(t, failures, Failure{Foreground: "brand", Background: "subtle", Ratio: 3.99, Minimum: 4.5})
}

// A pair exactly at its minimum passes: the ratio is compared, not its cut.
func TestCheck_APairAtItsMinimumPasses(t *testing.T) {
	colors := blueberryLight()
	colors["ink-muted"] = "#767676" // 4.54:1 on white
	colors["surface"] = "#ffffff"
	colors["line-strong"] = "#949494" // 3.03:1 on white
	failures, err := Check(colors)
	require.NoError(t, err)
	for _, f := range failures {
		assert.NotEqual(t, "surface", f.Background, "%s on the surface", f.Foreground)
	}
}

func TestCheck_RefusesAMissingTokenOrAValueThatIsNotAColor(t *testing.T) {
	missing := blueberryLight()
	delete(missing, "caution-soft")
	_, err := Check(missing)
	require.ErrorContains(t, err, "caution-soft")

	notAColor := blueberryLight()
	notAColor["note-ink"] = "#abc"
	_, err = Check(notAColor)
	require.ErrorContains(t, err, "note-ink")
}
