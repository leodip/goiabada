// Package brandkit holds what a brand's corners and font family draw (#813), which both
// applications draw alike: the auth server sets them in a brand's full stylesheet, on its own pages
// and the admin console's end-user pages, and the console's brand editor sets them on its sample of a
// sign-in page as they are picked, before the brand is saved. Drawn from one place, the sample cannot
// show a family or a corner shape the saved brand would draw differently.
//
// A choice is named by the value a brand stores. Rounded corners and the System UI family are
// today's look, ui.css's and main.css's own tokens, so they set nothing, and a brand nobody has
// changed is drawn exactly as before the kit.
package brandkit

// Radii are the two radius tokens ui.css declares for a corner shape: Control, --radius-control,
// rounds a control, and Panel, --radius-panel, a panel, the sign-in card among them.
type Radii struct {
	Control string `json:"control"`
	Panel   string `json:"panel"`
}

// cornerRadii are the radii of each corner shape but rounded. Square rounds nothing. Pill rounds a
// single-line control fully, and the card and the other panels to 1.5rem, which leaves their content
// unclipped; ui.css holds a multi-line box drawn with --radius-control (a text area, a notice, a
// list) to 1rem, so it is rounded only as far as its content stays unclipped too.
var cornerRadii = map[string]Radii{
	"square": {Control: "0", Panel: "0"},
	"pill":   {Control: "9999px", Panel: "1.5rem"},
}

// UploadedFontFamily is the family name a brand's uploaded font is given in its @font-face rules,
// which the uploaded font's list names first.
const UploadedFontFamily = `"brand-font"`

// systemUIStack is main.css's --font-sans, the System UI family, which follows an uploaded font as
// its fallback: text is drawn in it at once while the font loads, and for any character the font
// lacks (#813 decision 7).
const systemUIStack = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', 'Noto Sans', Arial, " +
	"sans-serif, 'Apple Color Emoji', 'Segoe UI Emoji', 'Segoe UI Symbol', 'Noto Color Emoji'"

// fontStacks are the font-family lists of the five system families besides System UI, each a list
// of fonts a visitor's device already has, so neither the server nor a visitor downloads a font for
// them (#813 decision 7): the matching text stacks of Modern Font Stacks (modernfontstacks.com,
// public domain), Humanist, Geometric Humanist, Transitional, Neo-Grotesque and Rounded Sans. The
// uploaded font's is its family followed by System UI.
var fontStacks = map[string]string{
	"humanist":      "Seravek, 'Gill Sans Nova', Ubuntu, Calibri, 'DejaVu Sans', source-sans-pro, sans-serif",
	"geometric":     "Avenir, Montserrat, Corbel, 'URW Gothic', source-sans-pro, sans-serif",
	"serif":         "Charter, 'Bitstream Charter', 'Sitka Text', Cambria, serif",
	"neo-grotesque": "Inter, Roboto, 'Helvetica Neue', 'Arial Nova', 'Nimbus Sans', Arial, sans-serif",
	"rounded":       "ui-rounded, 'Hiragino Maru Gothic ProN', Quicksand, Comfortaa, Manjari, 'Arial Rounded MT', 'Arial Rounded MT Bold', Calibri, source-sans-pro, sans-serif",
	"uploaded":      UploadedFontFamily + ", " + systemUIStack,
}

// CornerRadii returns the radii of corners, a brand's stored corner shape, and whether it sets any:
// rounded, today's, and a value that is no corner shape set none.
func CornerRadii(corners string) (Radii, bool) {
	radii, ok := cornerRadii[corners]
	return radii, ok
}

// FontStack returns the font-family list font, a brand's stored family, draws its text in, as
// --font-sans, and whether it sets one: System UI, today's, and a value that is no family set none.
// The uploaded font's list names UploadedFontFamily, which only a page that declares the font's
// files draws; the auth server sets it only while a regular font file fills its slot.
func FontStack(font string) (string, bool) {
	stack, ok := fontStacks[font]
	return stack, ok
}
