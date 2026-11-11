// Package brandkit holds what a brand's kit draws (#813), which both applications draw alike: its
// corners, its font family, its uploaded font's weights and its background's fit. The auth server
// sets them in a brand's full stylesheet, on its own pages and the admin console's end-user pages,
// and the console's brand editor sets them on its sample of a sign-in page as they are picked, before
// the brand is saved. Drawn from one place, the sample cannot show a family, a corner shape or a fit
// the saved brand would draw differently. It also holds each kind of asset's byte limit, which the
// auth server holds an upload to and the console's request-body table sizes its upload routes from.
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

// The most bytes an upload of each kind of brand asset may hold, fixed so the admin API behaves alike
// on every deployment (#813 decision 3): a logo or a dark logo, a favicon, a background image and a
// font file.
const (
	LogoMaxBytes       = 1 << 20
	FaviconMaxBytes    = 1 << 20
	BackgroundMaxBytes = 2 << 20
	FontMaxBytes       = 2 << 20
)

// The weights each file of an uploaded font draws while both are uploaded (#813 decision 7): the
// regular file those up to 500, the bold one the heavier ones. A regular file alone declares no
// weight, so it draws every weight.
const (
	RegularFontWeights = "1 500"
	BoldFontWeights    = "501 1000"
)

// Background is how a background image is laid out at a fit, as CSS values: its background-size,
// background-position and background-repeat, an empty one left as CSS's initial value. On a page,
// where the image is drawn behind the window, the auth server also fixes a cover or contained image
// to the window; the editor's sample is no window, so that is the stylesheet's alone.
type Background struct {
	Size     string `json:"size"`
	Position string `json:"position"`
	Repeat   string `json:"repeat"`
}

// backgrounds are the layouts of the fits but cover: contained, the whole image centred with the
// theme's background color around it, and tiled, repeated at its own size.
var backgrounds = map[string]Background{
	"contain": {Size: "contain", Position: "center", Repeat: "no-repeat"},
	"tile":    {Repeat: "repeat"},
}

// coverBackground covers the area with the image, centred, cropping what overflows.
var coverBackground = Background{Size: "cover", Position: "center", Repeat: "no-repeat"}

// BackgroundLayout returns how a background image is laid out at fit, a brand's stored background fit.
// A value that is none of the three, which no write stores, is laid out as cover, the fit migration
// 000091 gives every brand.
func BackgroundLayout(fit string) Background {
	if layout, ok := backgrounds[fit]; ok {
		return layout
	}
	return coverBackground
}
