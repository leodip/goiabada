package palette

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The 23 color tokens a palette sets for each mode.
var allTokens = []string{
	"brand", "brand-soft", "brand-strong", "canvas", "caution-ink", "caution-soft", "danger",
	"danger-ink", "danger-soft", "danger-strong", "focus", "ink", "ink-muted", "line", "line-strong",
	"note-ink", "note-soft", "on-brand", "on-danger", "positive-ink", "positive-soft", "subtle",
	"surface",
}

// The eight tokens a basic palette works out from its four colors, beside Blueberry's eleven
// status tokens.
var workedOutTokens = []string{"subtle", "line", "line-strong", "ink-muted", "brand-strong", "on-brand", "brand-soft", "focus"}

// Blueberry's status colors, as the built-in theme holds them (the auth server's web tests hold
// what Derive answers to the theme itself).
var blueberryStatus = map[string]map[string]string{
	"light": {
		"danger": "#b42318", "danger-strong": "#8f1c13", "on-danger": "#ffffff", "danger-soft": "#fdeceb",
		"danger-ink": "#8f1c13", "positive-soft": "#e3f3e8", "positive-ink": "#17612f",
		"caution-soft": "#fdf2d6", "caution-ink": "#6b4400", "note-soft": "#e6edfb", "note-ink": "#1d4796",
	},
	"dark": {
		"danger": "#ff8f85", "danger-strong": "#ffb0a8", "on-danger": "#330b07", "danger-soft": "#3a1714",
		"danger-ink": "#ffb4ab", "positive-soft": "#11291a", "positive-ink": "#8fd6a5",
		"caution-soft": "#2e2410", "caution-ink": "#f0c96a", "note-soft": "#142340", "note-ink": "#a8c7ff",
	},
}

// vector is one case of testdata/vectors.json, which the probe beside #815's agreement computed in
// JavaScript before any of this package's derivation existed: four entered colors, the eight
// colors worked out from them, and the pairs of the whole palette that still fail.
type vector struct {
	Theme        string            `json:"theme"`
	Mode         string            `json:"mode"`
	What         string            `json:"what"`
	StatusColors string            `json:"statusColors"`
	Input        map[string]string `json:"input"`
	WorkedOut    map[string]string `json:"workedOut"`
	HandMade     map[string]string `json:"handMade"`
	Warnings     []struct {
		Foreground string  `json:"foreground"`
		Background string  `json:"background"`
		Ratio      float64 `json:"ratio"`
		Minimum    float64 `json:"minimum"`
	} `json:"warnings"`
}

type vectors struct {
	PairsPerMode int      `json:"pairsPerMode"`
	BuiltIn      []vector `json:"builtIn"`
	ContrastPass []vector `json:"contrastPass"`
	Edge         []vector `json:"edge"`
}

func readVectors(t *testing.T) vectors {
	t.Helper()
	b, err := os.ReadFile("testdata/vectors.json")
	require.NoError(t, err)
	var v vectors
	require.NoError(t, json.Unmarshal(b, &v))
	require.Equal(t, 35, v.PairsPerMode, "the vectors were computed on the shared list")
	require.Len(t, v.BuiltIn, 14, "the seven built-in themes but High contrast, in two modes")
	require.Len(t, v.ContrastPass, 10)
	require.Len(t, v.Edge, 8)
	return v
}

// Each vector's four colors give exactly the probe's worked-out colors and failing pairs (#815
// decisions 4 and 13): the built-in themes rebuilt from their own four colors, seeded sets where the
// contrast pass moved at least two colors, and the edge cases.
func TestDerive_TheProbesVectors(t *testing.T) {
	v := readVectors(t)
	groups := map[string][]vector{"built-in": v.BuiltIn, "contrast pass": v.ContrastPass, "edge": v.Edge}
	for _, group := range slices.Sorted(maps.Keys(groups)) {
		for n, vec := range groups[group] {
			name := fmt.Sprintf("%s %d %s%s %s", group, n, vec.Theme, vec.What, vec.Mode)
			t.Run(name, func(t *testing.T) {
				got, err := Derive(vec.Input)
				require.NoError(t, err)

				for _, token := range []string{"canvas", "surface", "ink", "brand"} {
					assert.Equal(t, vec.Input[token], got[token], "%s, entered", token)
				}
				for _, token := range workedOutTokens {
					assert.Equal(t, vec.WorkedOut[token], got[token], "%s, worked out", token)
				}

				want := []Failure{}
				for _, w := range vec.Warnings {
					want = append(want, Failure{Foreground: w.Foreground, Background: w.Background, Ratio: w.Ratio, Minimum: w.Minimum})
				}
				failures, err := Check(got)
				require.NoError(t, err)
				assert.Equal(t, want, failures)
			})
		}
	}
}

// A mode takes Blueberry's light status colors when its text is darker than its card, and the dark
// ones otherwise, whichever column it is typed in (#815 decision 13): the edge cases include a dark
// design in the Light column, a navy card with white text on a pale background, and text the
// color of its card.
func TestDerive_StatusColorsFollowTheModesDirection(t *testing.T) {
	for _, vec := range readVectors(t).Edge {
		t.Run(vec.What, func(t *testing.T) {
			require.Contains(t, []string{"light", "dark"}, vec.StatusColors)
			got, err := Derive(vec.Input)
			require.NoError(t, err)
			for token, want := range blueberryStatus[vec.StatusColors] {
				assert.Equal(t, want, got[token], token)
			}
		})
	}

	light, err := Derive(map[string]string{"canvas": "#f4f5f7", "surface": "#ffffff", "ink": "#1a1f29", "brand": "#2456c4"})
	require.NoError(t, err)
	dark, err := Derive(map[string]string{"canvas": "#0f1217", "surface": "#171b22", "ink": "#e6e8ec", "brand": "#8ab4ff"})
	require.NoError(t, err)
	for token := range blueberryStatus["light"] {
		assert.Equal(t, blueberryStatus["light"][token], light[token], "light %s", token)
		assert.Equal(t, blueberryStatus["dark"][token], dark[token], "dark %s", token)
	}
}

// Derive answers the 23 tokens, each a color in lower case but the four entered ones, which come
// back exactly as entered, in either case.
func TestDerive_AnswersEveryTokenAndTheEnteredColorsAsEntered(t *testing.T) {
	entered := map[string]string{"canvas": "#F4F5F7", "surface": "#FFFFFF", "ink": "#1A1F29", "brand": "#2456C4"}
	got, err := Derive(entered)
	require.NoError(t, err)
	assert.Equal(t, allTokens, slices.Sorted(maps.Keys(got)))
	for token, value := range got {
		if want, ok := entered[token]; ok {
			assert.Equal(t, want, value, token)
			continue
		}
		assert.True(t, IsColor(value), "%s is %q", token, value)
		assert.Equal(t, strings.ToLower(value), value, "%s is in lower case", token)
	}
	assert.Equal(t, "#2456c4", got["focus"], "the focus ring is the brand color")
	assert.Equal(t, "#eceef2", got["subtle"], "the colors worked out from upper case are those worked out from lower case")

	assert.Equal(t, map[string]string{"canvas": "#F4F5F7", "surface": "#FFFFFF", "ink": "#1A1F29", "brand": "#2456C4"}, entered,
		"Derive leaves the map it is given as it was")
}

func TestDerive_RefusesAnythingButFourColors(t *testing.T) {
	four := func() map[string]string {
		return map[string]string{"canvas": "#f4f5f7", "surface": "#ffffff", "ink": "#1a1f29", "brand": "#2456c4"}
	}
	for _, tc := range []struct {
		name    string
		change  func(map[string]string)
		mention string
	}{
		{"no brand color", func(m map[string]string) { delete(m, "brand") }, "brand"},
		{"no card", func(m map[string]string) { delete(m, "surface") }, "surface"},
		{"a three-digit value", func(m map[string]string) { m["ink"] = "#000" }, "ink"},
		{"a color name", func(m map[string]string) { m["canvas"] = "white" }, "canvas"},
		{"one of the other 19", func(m map[string]string) { m["subtle"] = "#eeeeee" }, "subtle"},
		{"a name that is no token", func(m map[string]string) { m["accent"] = "#eeeeee" }, "accent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entered := four()
			tc.change(entered)
			got, err := Derive(entered)
			require.ErrorContains(t, err, tc.mention)
			assert.Nil(t, got)
		})
	}
	_, err := Derive(nil)
	assert.Error(t, err)
}

// The property of #815 decision 4, over the 4,000 sets of four colors the probe's wide.mjs draws
// from all of sRGB with its seeded generator, kept when their own four pairs pass: no pair between
// a worked-out color and an entered or another worked-out color fails. Pairs with a status color
// in them are outside it. The counts are the probe's: 921 sets fail some pair, 7 of them a pair with
// a worked-out color in it, muted text on a status background each time.
func TestDerive_NoPairOfWorkedOutAndEnteredColorsFailsOverAllOfSRGB(t *testing.T) {
	seed := uint32(2815)
	next := func() string {
		var b strings.Builder
		b.WriteByte('#')
		for range 3 {
			seed = seed*1664525 + 1013904223
			fmt.Fprintf(&b, "%02x", seed>>24)
		}
		return b.String()
	}
	passes := func(fg, bg string) bool {
		ratio, err := ContrastRatio(fg, bg)
		require.NoError(t, err)
		return ratio >= TextMinimum
	}

	var sets []map[string]string
	for len(sets) < 4000 {
		m := map[string]string{"canvas": next(), "surface": next(), "ink": next(), "brand": next()}
		if passes(m["ink"], m["canvas"]) && passes(m["ink"], m["surface"]) && passes(m["brand"], m["canvas"]) && passes(m["brand"], m["surface"]) {
			sets = append(sets, m)
		}
	}
	require.Equal(t, map[string]string{"canvas": "#3524f4", "surface": "#52045f", "ink": "#d6e136", "brand": "#dafb5a"}, sets[0],
		"the first set the probe's generator draws")
	require.Equal(t, map[string]string{"canvas": "#96c4df", "surface": "#71e4a0", "ink": "#43216f", "brand": "#11393c"}, sets[3999],
		"the last set the probe's generator draws")

	isStatus := func(token string) bool { _, ok := blueberryStatus["light"][token]; return ok }
	isWorkedOut := func(token string) bool { return slices.Contains(workedOutTokens, token) }
	anyFailing, withWorkedOut := 0, 0
	for _, entered := range sets {
		got, err := Derive(entered)
		require.NoError(t, err)
		for token, value := range entered {
			require.Equal(t, value, got[token], "%v: %s comes back as entered", entered, token)
		}
		failures, err := Check(got)
		require.NoError(t, err)
		if len(failures) > 0 {
			anyFailing++
		}
		touched := false
		for _, f := range failures {
			if !isWorkedOut(f.Foreground) && !isWorkedOut(f.Background) {
				continue
			}
			touched = true
			if !isStatus(f.Foreground) && !isStatus(f.Background) {
				t.Errorf("%v: %s on %s is %.2f:1, below %.1f:1", entered, f.Foreground, f.Background, f.Ratio, f.Minimum)
			}
		}
		if touched {
			withWorkedOut++
		}
	}
	assert.Equal(t, 921, anyFailing)
	assert.Equal(t, 7, withWorkedOut)
}
