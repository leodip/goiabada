package brandkit

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Rounded is today's look, ui.css's own radii, so it sets none (#813 "Assumed, not asked"). Square
// rounds nothing; pill rounds a single-line control fully and a panel to 1.5rem.
func TestCornerRadii(t *testing.T) {
	for _, tc := range []struct {
		corners string
		want    Radii
		sets    bool
	}{
		{"square", Radii{Control: "0", Panel: "0"}, true},
		{"pill", Radii{Control: "9999px", Panel: "1.5rem"}, true},
		{"rounded", Radii{}, false},
		{"", Radii{}, false},
		{"oval", Radii{}, false},
	} {
		t.Run(tc.corners, func(t *testing.T) {
			radii, sets := CornerRadii(tc.corners)
			assert.Equal(t, tc.want, radii)
			assert.Equal(t, tc.sets, sets)
		})
	}
}

// systemUI is main.css's --font-sans, today's family.
const systemUI = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', 'Noto Sans', Arial, " +
	"sans-serif, 'Apple Color Emoji', 'Segoe UI Emoji', 'Segoe UI Symbol', 'Noto Color Emoji'"

// Each of the five system families besides System UI is the matching text stack of Modern Font Stacks
// (#813 decision 7). System UI is today's family, so it sets none, and the uploaded font is followed
// by System UI as its fallback.
func TestFontStack(t *testing.T) {
	for _, tc := range []struct {
		font string
		want string
		sets bool
	}{
		{"humanist", "Seravek, 'Gill Sans Nova', Ubuntu, Calibri, 'DejaVu Sans', source-sans-pro, sans-serif", true},
		{"geometric", "Avenir, Montserrat, Corbel, 'URW Gothic', source-sans-pro, sans-serif", true},
		{"serif", "Charter, 'Bitstream Charter', 'Sitka Text', Cambria, serif", true},
		{"neo-grotesque", "Inter, Roboto, 'Helvetica Neue', 'Arial Nova', 'Nimbus Sans', Arial, sans-serif", true},
		{"rounded", "ui-rounded, 'Hiragino Maru Gothic ProN', Quicksand, Comfortaa, Manjari, 'Arial Rounded MT', 'Arial Rounded MT Bold', Calibri, source-sans-pro, sans-serif", true},
		{"uploaded", `"brand-font", ` + systemUI, true},
		{"system-ui", "", false},
		{"", "", false},
		{"comic", "", false},
	} {
		t.Run(tc.font, func(t *testing.T) {
			stack, sets := FontStack(tc.font)
			assert.Equal(t, tc.want, stack)
			assert.Equal(t, tc.sets, sets)
		})
	}
}

// The byte limits of decision 3: a logo and a favicon up to 1 MiB, a background and a font up to 2 MiB.
func TestMaxBytes(t *testing.T) {
	assert.Equal(t, 1048576, LogoMaxBytes)
	assert.Equal(t, 1048576, FaviconMaxBytes)
	assert.Equal(t, 2097152, BackgroundMaxBytes)
	assert.Equal(t, 2097152, FontMaxBytes)
}

// With a bold file, the regular one draws the weights up to 500 and the bold one the heavier ones
// (#813 decision 7).
func TestFontWeights(t *testing.T) {
	assert.Equal(t, "1 500", RegularFontWeights)
	assert.Equal(t, "501 1000", BoldFontWeights)
}

// Cover and contain centre the image once, unrepeated; tile repeats it at its own size. A fit no
// write stores is laid out as cover.
func TestBackgroundLayout(t *testing.T) {
	cover := Background{Size: "cover", Position: "center", Repeat: "no-repeat"}
	for _, tc := range []struct {
		fit  string
		want Background
	}{
		{"cover", cover},
		{"contain", Background{Size: "contain", Position: "center", Repeat: "no-repeat"}},
		{"tile", Background{Repeat: "repeat"}},
		{"", cover},
		{"stretch", cover},
	} {
		t.Run(tc.fit, func(t *testing.T) {
			assert.Equal(t, tc.want, BackgroundLayout(tc.fit))
		})
	}
}
