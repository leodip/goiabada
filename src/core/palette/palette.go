// Package palette holds what a brand's colors are checked against (#815): the shared list of the
// pairs of color tokens the pages draw text, a boundary or a focus ring in, each at its minimum
// contrast, WCAG 2.2's contrast ratio, and the check that answers a palette's failing pairs. The
// built-in themes are held to the list by the auth server's web tests, and a custom palette is
// checked against the same list, so a warning names a pair the built-in themes are held to. It also
// works out a basic palette's colors from the four entered for a mode (Derive), in OKLCH.
//
// A color is `#` and six hexadecimal digits, in either case; nothing else is one.
package palette

import (
	"math"
	"strconv"

	"github.com/leodip/goiabada/core/errs"
)

// The two minimums a pair is held to: 4.5:1 for text, WCAG 2.2 SC 1.4.3, Contrast (Minimum), and
// 3:1 for a boundary or the focus ring, SC 1.4.11, Non-text Contrast.
const (
	TextMinimum    = 4.5
	NonTextMinimum = 3.0
)

// Pair is a foreground color token drawn on a background color token, and the contrast ratio the
// two must reach.
type Pair struct {
	Foreground string
	Background string
	Minimum    float64
}

// pairs is the shared list, each pair once at its strictest minimum (#815 decision 5). The text
// pairs come first: every pair a component draws text in, a link among them, since a link is drawn
// in the brand color on a hovered table row and inside note and caution notices and in the strong
// shade when hovered there (#810 decision 9). The brand color on the subtle background is a text
// pair for that reason, though it is also the boundary of a selected item. Then the boundaries and
// the focus ring.
var pairs = []Pair{
	{"ink", "canvas", TextMinimum}, {"ink", "surface", TextMinimum},
	{"ink", "subtle", TextMinimum}, {"ink", "brand-soft", TextMinimum},
	{"ink-muted", "canvas", TextMinimum}, {"ink-muted", "surface", TextMinimum},
	{"ink-muted", "subtle", TextMinimum}, {"ink-muted", "brand-soft", TextMinimum},
	{"brand", "canvas", TextMinimum}, {"brand", "surface", TextMinimum},
	{"brand-strong", "surface", TextMinimum},
	{"on-brand", "brand", TextMinimum}, {"on-brand", "brand-strong", TextMinimum},
	{"on-danger", "danger", TextMinimum}, {"on-danger", "danger-strong", TextMinimum},
	{"danger-ink", "canvas", TextMinimum}, {"danger-ink", "surface", TextMinimum},
	{"danger-ink", "danger-soft", TextMinimum},
	{"positive-ink", "positive-soft", TextMinimum}, {"caution-ink", "caution-soft", TextMinimum},
	{"note-ink", "note-soft", TextMinimum},
	{"ink-muted", "positive-soft", TextMinimum}, {"ink-muted", "caution-soft", TextMinimum},
	{"brand", "subtle", TextMinimum}, {"brand", "note-soft", TextMinimum},
	{"brand", "caution-soft", TextMinimum},
	{"brand-strong", "subtle", TextMinimum}, {"brand-strong", "note-soft", TextMinimum},
	{"brand-strong", "caution-soft", TextMinimum},

	{"line-strong", "canvas", NonTextMinimum}, {"line-strong", "surface", NonTextMinimum},
	{"focus", "canvas", NonTextMinimum}, {"focus", "surface", NonTextMinimum},
	{"focus", "subtle", NonTextMinimum},
	{"danger", "surface", NonTextMinimum},
}

// Pairs answers the shared list, in its order, as a copy the caller may change.
func Pairs() []Pair {
	return append([]Pair(nil), pairs...)
}

// IsColor reports whether s is a color: `#` and six hexadecimal digits, in either case.
func IsColor(s string) bool {
	if len(s) != 7 || s[0] != '#' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isHexDigit(s[i]) {
			return false
		}
	}
	return true
}

func isHexDigit(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// luminance is a color's relative luminance, by WCAG 2.2's definition. The color must pass IsColor.
func luminance(color string) float64 {
	channel := func(hex string) float64 {
		v, _ := strconv.ParseUint(hex, 16, 8)
		c := float64(v) / 255
		if c <= 0.04045 {
			return c / 12.92
		}
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	return 0.2126*channel(color[1:3]) + 0.7152*channel(color[3:5]) + 0.0722*channel(color[5:7])
}

// ContrastRatio is WCAG 2.2's contrast ratio of two colors, (L1 + 0.05) / (L2 + 0.05), L1 the
// lighter one's relative luminance: from 1, for two colors alike, to 21, for black and white. Either
// order gives the same ratio.
func ContrastRatio(foreground, background string) (float64, error) {
	for _, c := range []string{foreground, background} {
		if !IsColor(c) {
			return 0, errs.Errorf("%q is not a #rrggbb color", c)
		}
	}
	lighter, darker := luminance(foreground), luminance(background)
	if lighter < darker {
		lighter, darker = darker, lighter
	}
	return (lighter + 0.05) / (darker + 0.05), nil
}

// Failure is a pair of the shared list that falls below its minimum. Ratio is its contrast ratio
// cut to two decimals, never rounded up, so a pair at 4.496:1 reads 4.49 and never its minimum.
type Failure struct {
	Foreground string
	Background string
	Ratio      float64
	Minimum    float64
}

// Check answers the pairs of the shared list that colors, a map from each color token's name to its
// value, fails, in the list's order, and an empty list when none does. A pair passes or fails on
// its exact ratio. It refuses colors that lack a token the list names or hold a value that is not a
// color, naming the token.
func Check(colors map[string]string) ([]Failure, error) {
	failures := []Failure{}
	for _, p := range pairs {
		ratio, err := pairRatio(colors, p)
		if err != nil {
			return nil, err
		}
		if ratio < p.Minimum {
			failures = append(failures, Failure{
				Foreground: p.Foreground,
				Background: p.Background,
				Ratio:      cut(ratio),
				Minimum:    p.Minimum,
			})
		}
	}
	return failures, nil
}

func pairRatio(colors map[string]string, p Pair) (float64, error) {
	for _, token := range []string{p.Foreground, p.Background} {
		value, ok := colors[token]
		if !ok {
			return 0, errs.Errorf("the palette has no %s color", token)
		}
		if !IsColor(value) {
			return 0, errs.Errorf("the palette's %s color, %q, is not a #rrggbb color", token, value)
		}
	}
	return ContrastRatio(colors[p.Foreground], colors[p.Background])
}

// cut drops a ratio's digits past the second decimal. Hundredths are counted down when the product
// rounded up to the next one, so the answer is never above the ratio.
func cut(ratio float64) float64 {
	hundredths := math.Floor(ratio * 100)
	if hundredths/100 > ratio {
		hundredths--
	}
	return hundredths / 100
}
