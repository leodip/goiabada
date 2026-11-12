package palette

import (
	"fmt"
	"math"
	"strconv"

	"github.com/leodip/goiabada/core/errs"
)

// OKLCH is a color in OKLCH, the polar form of Björn Ottosson's OKLab, as CSS Color Module Level 4
// defines it: L its lightness, from 0 for black to 1 for white, C its chroma, and H its hue in
// degrees, from 0 up to 360. Lightness steps in it look even, which is why a basic palette is
// worked out in it.
type OKLCH struct {
	L, C, H float64
}

// ToOKLCH converts a color to OKLCH. It refuses a value that is not a color.
func ToOKLCH(color string) (OKLCH, error) {
	if !IsColor(color) {
		return OKLCH{}, errs.Errorf("%q is not a #rrggbb color", color)
	}
	o := toLCH(color)
	h := o.h * 180 / math.Pi
	if h < 0 {
		h += 360
	}
	return OKLCH{L: o.l, C: o.c, H: h}, nil
}

// Color answers o as a color, in lower case. A lightness past either end is white or black, and a
// chroma sRGB cannot show at o's lightness and hue is lowered until it can.
func (o OKLCH) Color() string {
	return fromLCH(lch{l: o.L, c: o.C, h: o.H * math.Pi / 180})
}

// lch is OKLCH with its hue in radians, the form the derivation computes in, so that its arithmetic
// is the probe's (#815 decision 4) operation for operation.
type lch struct {
	l, c, h float64
}

// channels answers a color's three sRGB channels, each from 0 to 1. The color must pass IsColor.
func channels(color string) [3]float64 {
	var rgb [3]float64
	for i := range rgb {
		v, _ := strconv.ParseUint(color[1+2*i:3+2*i], 16, 8)
		rgb[i] = float64(v) / 255
	}
	return rgb
}

// toLinear undoes sRGB's transfer function.
func toLinear(c float64) float64 {
	if c <= 0.04045 {
		return c / 12.92
	}
	return math.Pow((c+0.055)/1.055, 2.4)
}

// toGamma applies sRGB's transfer function.
func toGamma(c float64) float64 {
	if c <= 0.0031308 {
		return 12.92 * c
	}
	return 1.055*math.Pow(c, 1/2.4) - 0.055
}

// toLCH converts a color, which must pass IsColor, to OKLCH by Ottosson's matrices.
func toLCH(color string) lch {
	rgb := channels(color)
	r, g, b := toLinear(rgb[0]), toLinear(rgb[1]), toLinear(rgb[2])
	l := math.Cbrt(0.4122214708*r + 0.5363325363*g + 0.0514459929*b)
	m := math.Cbrt(0.2119034982*r + 0.6806995451*g + 0.1073969566*b)
	s := math.Cbrt(0.0883024619*r + 0.2817188376*g + 0.6299787005*b)
	L := 0.2104542553*l + 0.793617785*m - 0.0040720468*s
	A := 1.9779984951*l - 2.428592205*m + 0.4505937099*s
	B := 0.0259040371*l + 0.7827717662*m - 0.808675766*s
	return lch{l: L, c: math.Hypot(A, B), h: math.Atan2(B, A)}
}

// linearRGB converts OKLCH to linear sRGB channels, which fall outside 0 to 1 for a color sRGB
// cannot show.
func linearRGB(o lch) [3]float64 {
	A, B := o.c*math.Cos(o.h), o.c*math.Sin(o.h)
	l := cube(o.l + 0.3963377774*A + 0.2158037573*B)
	m := cube(o.l - 0.1055613458*A - 0.0638541728*B)
	s := cube(o.l - 0.0894841775*A - 1.291485548*B)
	return [3]float64{
		4.0767416621*l - 3.3077115913*m + 0.2309699292*s,
		-1.2684380046*l + 2.6097574011*m - 0.3413193965*s,
		-0.0041960863*l - 0.7034186147*m + 1.707614701*s,
	}
}

func cube(x float64) float64 {
	return x * x * x
}

// inGamut reports whether sRGB can show linear channels, allowing what rounding leaves.
func inGamut(rgb [3]float64) bool {
	for _, c := range rgb {
		if c < -1e-6 || c > 1+1e-6 {
			return false
		}
	}
	return true
}

// fromLCH answers o as a color: its lightness held between 0 and 1, and its chroma, when sRGB cannot
// show it, lowered by bisection to the highest it can at o's lightness and hue.
func fromLCH(o lch) string {
	o.l = math.Min(1, math.Max(0, o.l))
	if !inGamut(linearRGB(o)) {
		lo, hi := 0.0, o.c
		for range 24 {
			mid := (lo + hi) / 2
			if inGamut(linearRGB(lch{l: o.l, c: mid, h: o.h})) {
				lo = mid
			} else {
				hi = mid
			}
		}
		o.c = lo
	}
	rgb := linearRGB(o)
	var hex [3]int
	for i, c := range rgb {
		hex[i] = int(math.Round(math.Min(1, math.Max(0, toGamma(math.Min(1, math.Max(0, c))))) * 255))
	}
	return fmt.Sprintf("#%02x%02x%02x", hex[0], hex[1], hex[2])
}
