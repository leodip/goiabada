package palette

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Published OKLCH values of sRGB colors, from CSS Color Module Level 4's OKLab conversion: sRGB red
// is oklch(62.796% 0.25768 29.2339), lime oklch(86.644% 0.29483 142.4953) and blue
// oklch(45.201% 0.31321 264.052). White and black have no chroma.
func TestToOKLCH(t *testing.T) {
	for _, tc := range []struct {
		color string
		want  OKLCH
	}{
		{"#ff0000", OKLCH{L: 0.62796, C: 0.25768, H: 29.2339}},
		{"#00ff00", OKLCH{L: 0.86644, C: 0.29483, H: 142.4953}},
		{"#0000ff", OKLCH{L: 0.45201, C: 0.31321, H: 264.052}},
		{"#0000FF", OKLCH{L: 0.45201, C: 0.31321, H: 264.052}},
	} {
		t.Run(tc.color, func(t *testing.T) {
			got, err := ToOKLCH(tc.color)
			require.NoError(t, err)
			assert.InDelta(t, tc.want.L, got.L, 0.00001)
			assert.InDelta(t, tc.want.C, got.C, 0.00001)
			assert.InDelta(t, tc.want.H, got.H, 0.001)
		})
	}

	for color, l := range map[string]float64{"#ffffff": 1, "#000000": 0} {
		got, err := ToOKLCH(color)
		require.NoError(t, err)
		assert.InDelta(t, l, got.L, 0.00001, color)
		assert.InDelta(t, 0, got.C, 0.00001, color)
	}
}

func TestToOKLCH_RefusesAValueThatIsNotAColor(t *testing.T) {
	for _, value := range []string{"", "#fff", "red", "#ff000080"} {
		_, err := ToOKLCH(value)
		assert.Error(t, err, "%q", value)
	}
}

// Every #rrggbb of a sample spread over the whole of sRGB comes back from OKLCH as itself.
func TestOKLCH_ColorRoundTrip(t *testing.T) {
	levels := []int{0, 1, 2, 17, 34, 51, 68, 85, 102, 119, 127, 128, 136, 153, 170, 187, 204, 221, 238, 253, 254, 255}
	for _, r := range levels {
		for _, g := range levels {
			for _, b := range levels {
				color := fmt.Sprintf("#%02x%02x%02x", r, g, b)
				o, err := ToOKLCH(color)
				require.NoError(t, err)
				if got := o.Color(); got != color {
					t.Errorf("%s is oklch(%.5f %.5f %.3f), which comes back as %s", color, o.L, o.C, o.H, got)
				}
			}
		}
	}
	o, err := ToOKLCH("#2456C4")
	require.NoError(t, err)
	assert.Equal(t, "#2456c4", o.Color(), "a color comes back in lower case")
}

// A color sRGB cannot show keeps its lightness and hue, and gives up chroma until it can be shown;
// a lightness past either end is white or black.
func TestOKLCH_ColorLowersAChromaSRGBCannotShow(t *testing.T) {
	got := OKLCH{L: 0.7, C: 0.4, H: 145}.Color()
	require.True(t, IsColor(got), got)
	back, err := ToOKLCH(got)
	require.NoError(t, err)
	assert.InDelta(t, 0.7, back.L, 0.005)
	assert.InDelta(t, 145, back.H, 1)
	assert.Less(t, back.C, 0.3)
	assert.Greater(t, back.C, 0.15)

	assert.Equal(t, "#ffffff", OKLCH{L: 1.2, C: 0, H: 0}.Color())
	assert.Equal(t, "#000000", OKLCH{L: -0.1, C: 0, H: 0}.Color())
}
