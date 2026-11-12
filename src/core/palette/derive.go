package palette

import (
	"math"
	"slices"
	"strings"

	"github.com/leodip/goiabada/core/errs"
)

// The four colors a basic palette is entered with, for each mode: the page's background (canvas),
// the card (surface), the text (ink) and the brand color.
var basicTokens = []string{"canvas", "surface", "ink", "brand"}

// Blueberry's eleven status colors, which a basic palette takes unchanged: the light set for a mode
// whose text is darker than its card, the dark set otherwise (#815 decision 13). The auth server's
// web tests hold them to the Blueberry theme itself.
var (
	blueberryLightStatus = map[string]string{
		"danger": "#b42318", "danger-strong": "#8f1c13", "on-danger": "#ffffff", "danger-soft": "#fdeceb",
		"danger-ink": "#8f1c13", "positive-soft": "#e3f3e8", "positive-ink": "#17612f",
		"caution-soft": "#fdf2d6", "caution-ink": "#6b4400", "note-soft": "#e6edfb", "note-ink": "#1d4796",
	}
	blueberryDarkStatus = map[string]string{
		"danger": "#ff8f85", "danger-strong": "#ffb0a8", "on-danger": "#330b07", "danger-soft": "#3a1714",
		"danger-ink": "#ffb4ab", "positive-soft": "#11291a", "positive-ink": "#8fd6a5",
		"caution-soft": "#2e2410", "caution-ink": "#f0c96a", "note-soft": "#142340", "note-ink": "#a8c7ff",
	}
)

// The step a contrast pass moves a color by in OKLCH lightness, and the most steps it takes.
const (
	seekStep  = 0.0025
	seekSteps = 400
)

// Derive works out a basic palette's mode from its four entered colors (#815 decision 4): entered
// maps each of canvas, surface, ink and brand to a color, and nothing else. It answers all 23 color
// tokens: the four entered colors exactly as entered, Blueberry's status colors for the mode's
// direction, and the other eight worked out in lower case. It is a pure function of the four.
//
// The mode is stepped as a light one when its text is darker than its card in OKLCH lightness, and
// as a dark one otherwise. The eight first take the lightness steps the built-in themes take; then
// the contrast pass moves those that carry text, a boundary or the focus ring until their pairs of
// the shared list pass, as far as they can go. It is a best effort: a pair can still fail, most
// often one between two entered colors or with a status color, and Check says which.
func Derive(entered map[string]string) (map[string]string, error) {
	for token, value := range entered {
		if !slices.Contains(basicTokens, token) {
			return nil, errs.Errorf("%q is not one of a basic palette's colors, which are canvas, surface, ink and brand", token)
		}
		if !IsColor(value) {
			return nil, errs.Errorf("the palette's %s color, %q, is not a #rrggbb color", token, value)
		}
	}
	for _, token := range basicTokens {
		if _, ok := entered[token]; !ok {
			return nil, errs.Errorf("the palette has no %s color", token)
		}
	}

	d := newDerivation(entered)
	d.steps()
	d.contrastPass()

	for _, token := range basicTokens {
		d.pal[token] = entered[token]
	}
	return d.pal, nil
}

// derivation is one mode being worked out: the four entered colors in lower case and in OKLCH, the
// direction the mode steps in, and the palette so far.
type derivation struct {
	canvas, surface, ink, brand  string
	inkLCH, surfaceLCH, brandLCH lch

	// dir is the way lightness moves from the card toward the text: -1 for a light mode, whose
	// text is darker than its card, and 1 for a dark one.
	dir float64
	// near is whichever of the background and the card is nearer the text in lightness, the card
	// when the two are as near.
	near    string
	nearLCH lch

	pal map[string]string
}

func newDerivation(entered map[string]string) *derivation {
	d := &derivation{
		canvas:  strings.ToLower(entered["canvas"]),
		surface: strings.ToLower(entered["surface"]),
		ink:     strings.ToLower(entered["ink"]),
		brand:   strings.ToLower(entered["brand"]),
	}
	canvasLCH := toLCH(d.canvas)
	d.inkLCH, d.surfaceLCH, d.brandLCH = toLCH(d.ink), toLCH(d.surface), toLCH(d.brand)
	d.dir = 1
	if d.inkLCH.l < d.surfaceLCH.l {
		d.dir = -1
	}
	d.near = d.surface
	if d.light() && canvasLCH.l < d.surfaceLCH.l || !d.light() && canvasLCH.l > d.surfaceLCH.l {
		d.near = d.canvas
	}
	d.nearLCH = toLCH(d.near)

	d.pal = map[string]string{"canvas": d.canvas, "surface": d.surface, "ink": d.ink, "brand": d.brand}
	for token, value := range d.status() {
		d.pal[token] = value
	}
	return d
}

func (d *derivation) light() bool {
	return d.dir < 0
}

// status answers Blueberry's status colors for the mode's direction (#815 decision 13).
func (d *derivation) status() map[string]string {
	if d.light() {
		return blueberryLightStatus
	}
	return blueberryDarkStatus
}

// byMode answers the light mode's value or the dark mode's.
func (d *derivation) byMode(light, dark float64) float64 {
	if d.light() {
		return light
	}
	return dark
}

// shift moves a color's lightness by dl and gives it chroma c, its hue kept.
func shift(color string, dl, c float64) string {
	o := toLCH(color)
	return fromLCH(lch{l: o.l + dl, c: c, h: o.h})
}

// steps works out the eight tokens by the lightness steps the built-in themes take, in OKLCH, with
// their small chroma changes.
func (d *derivation) steps() {
	dir := d.dir
	d.pal["subtle"] = shift(d.near, dir*d.byMode(0.02, 0.038), d.nearLCH.c+0.003)
	d.pal["line"] = shift(d.near, dir*d.byMode(0.08, 0.107), d.nearLCH.c+0.008)
	d.pal["line-strong"] = fromLCH(lch{l: 0.575, c: d.nearLCH.c + 0.02, h: d.nearLCH.h})
	d.pal["ink-muted"] = shift(d.ink, -dir*d.byMode(0.23, 0.2), d.inkLCH.c+0.007)
	d.pal["brand-strong"] = shift(d.brand, dir*d.byMode(0.08, 0.065), d.brandLCH.c*d.byMode(0.82, 0.74))
	softChroma := math.Min(0.055, d.brandLCH.c*0.46)
	if d.light() {
		softChroma = math.Min(0.024, d.brandLCH.c*0.14)
	}
	soft := toLCH(d.surface)
	d.pal["brand-soft"] = fromLCH(lch{l: soft.l + dir*d.byMode(0.058, 0.065), c: softChroma, h: d.brandLCH.h})
	d.pal["on-brand"] = d.onBrand()
	d.pal["focus"] = d.brand
}

// onBrand is the first of white, a dark tint of the brand color, and black that reaches 4.5:1 on
// both the brand color and brand-strong; when none does, the one whose lower ratio is highest.
func (d *derivation) onBrand() string {
	candidates := []string{
		"#ffffff",
		fromLCH(lch{l: 0.22, c: math.Min(d.brandLCH.c*0.45, 0.09), h: d.brandLCH.h}),
		"#000000",
	}
	lower := func(candidate string) float64 {
		return math.Min(contrast(candidate, d.pal["brand"]), contrast(candidate, d.pal["brand-strong"]))
	}
	for _, candidate := range candidates {
		if lower(candidate) >= TextMinimum {
			return candidate
		}
	}
	best, bestLower := candidates[0], -1.0
	for _, candidate := range candidates {
		if l := lower(candidate); l > bestLower+1e-9 {
			best, bestLower = candidate, l
		}
	}
	return best
}

// contrast is ContrastRatio of two colors known to be colors.
func contrast(a, b string) float64 {
	ratio, _ := ContrastRatio(a, b)
	return ratio
}

// contrastPass moves the worked-out colors until their pairs pass, in the order #815 decision 4
// sets: subtle gives way, the colors drawn on a background are moved toward the text, on-brand is
// chosen again, brand-soft gives way, and muted text is moved again or falls back to the text color.
func (d *derivation) contrastPass() {
	d.subtleGivesWay()

	far := 1.0
	if d.light() {
		far = 0
	}
	d.seek("ink-muted", []string{"canvas", "surface", "subtle", "brand-soft", "positive-soft", "caution-soft"}, TextMinimum, d.inkLCH.l)
	d.seek("line-strong", []string{"canvas", "surface"}, NonTextMinimum, far)
	d.seek("brand-strong", []string{"surface", "subtle", "note-soft", "caution-soft"}, TextMinimum, far)
	d.seek("focus", []string{"canvas", "surface", "subtle"}, NonTextMinimum, far)
	d.pal["on-brand"] = d.onBrand()

	d.brandSoftGivesWay()
	d.inkMutedOrInk()
}

// subtleGivesWay shrinks the subtle background's step from the near background, down to none,
// while the brand color or the text color would lose on it a text pair it holds on the near
// background; with no step left that keeps them, subtle is the near background itself.
func (d *derivation) subtleGivesWay() {
	holds := func(fg string) bool { return contrast(fg, d.near) >= TextMinimum }
	keeps := func(subtle string) bool {
		for _, fg := range []string{d.brand, d.ink} {
			if holds(fg) && contrast(fg, subtle) < TextMinimum {
				return false
			}
		}
		return true
	}
	step := d.byMode(0.02, 0.038)
	for step > 0 && !keeps(d.pal["subtle"]) {
		step = math.Max(0, step-0.002)
		d.pal["subtle"] = fromLCH(lch{l: d.nearLCH.l + d.dir*step, c: d.nearLCH.c + 0.003, h: d.nearLCH.h})
	}
	if !keeps(d.pal["subtle"]) {
		d.pal["subtle"] = d.near
	}
}

// seek moves token toward the text in lightness, its hue and chroma kept, until it reaches minimum
// on every one of backgrounds, or until a further step would pass the lightness limit.
func (d *derivation) seek(token string, backgrounds []string, minimum, limit float64) {
	o := toLCH(d.pal[token])
	color := d.pal[token]
	for n := 0; n < seekSteps && !d.reaches(color, backgrounds, minimum); n++ {
		next := o.l + d.dir*seekStep
		if d.dir < 0 && next < limit || d.dir > 0 && next > limit {
			break
		}
		o.l = next
		color = fromLCH(o)
	}
	d.pal[token] = color
}

func (d *derivation) reaches(color string, backgrounds []string, minimum float64) bool {
	for _, bg := range backgrounds {
		if contrast(color, d.pal[bg]) < minimum {
			return false
		}
	}
	return true
}

// brandSoftGivesWay shrinks brand-soft's step from the card, in twentieths, down to none, while the
// text color would lose on it the text pair it holds on the card.
func (d *derivation) brandSoftGivesWay() {
	if contrast(d.ink, d.surface) < TextMinimum || contrast(d.ink, d.pal["brand-soft"]) >= TextMinimum {
		return
	}
	soft := toLCH(d.pal["brand-soft"])
	full := soft.l - d.surfaceLCH.l
	color := d.surface
	for k := 19; k >= 1; k-- {
		c := fromLCH(lch{l: d.surfaceLCH.l + full*float64(k)/20, c: soft.c, h: soft.h})
		if contrast(d.ink, c) >= TextMinimum {
			color = c
			break
		}
	}
	d.pal["brand-soft"] = color
}

// inkMutedOrInk moves muted text toward the text color again, now brand-soft has given way, until it
// reaches 4.5:1 on every background it is drawn on. Muted text that reaches the text color's
// lightness with a pair still failing is the text color itself.
func (d *derivation) inkMutedOrInk() {
	backgrounds := []string{"canvas", "surface", "subtle", "brand-soft", "positive-soft", "caution-soft"}
	o := toLCH(d.pal["ink-muted"])
	color := d.pal["ink-muted"]
	reached := d.reaches(color, backgrounds, TextMinimum)
	for n := 0; n < seekSteps && !reached; n++ {
		next := o.l + d.dir*seekStep
		if d.dir < 0 && next < d.inkLCH.l || d.dir > 0 && next > d.inkLCH.l {
			break
		}
		o.l = next
		color = fromLCH(o)
		reached = d.reaches(color, backgrounds, TextMinimum)
	}
	if reached {
		d.pal["ink-muted"] = color
	} else {
		d.pal["ink-muted"] = d.ink
	}
}
