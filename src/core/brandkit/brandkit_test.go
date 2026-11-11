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
