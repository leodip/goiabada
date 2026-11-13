package render

import (
	"context"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/brandthemes"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/brandkit"
)

// EmailLook is what an email takes from its brand beyond what a page does (#817 decisions 2 and 4):
// whether it is drawn dark, which a dark brand is and a light or automatic one is not, the 23
// colors of that one mode, safe mode's in safe mode, its corner shape and font family, and the path,
// width and height of the logo it draws, the dark logo in a dark brand's email when there is one.
// Colors is nil for a brand that cannot be read, which an email draws unbranded.
type EmailLook struct {
	Dark       bool
	Colors     brandthemes.Palette
	Corners    record.BrandCorners
	Font       record.BrandFont
	Logo       string
	LogoWidth  int
	LogoHeight int
}

// EmailFrame is what the email layout draws its frame with, every value written inline on the
// element it styles, since many clients drop a style sheet and none resolves a CSS variable (#817).
//
// ColorScheme is the one scheme the email is drawn in, light or dark, which it declares. The colors
// are each a #rrggbb value, and each is used for what a page uses it for: Canvas behind the card,
// Surface the card, Line its border, Ink the text, InkMuted the app name, and Link a link, the
// brand's color. PanelRadius is the card's corner, in pixels, and FontFamily the text's font list.
// Each is a value html/template's style filter passes as it is: a color, a length, or a list of
// family names written unquoted (emailFontFamily).
// Logo is the logo's absolute URL, empty for none, drawn at LogoWidth by LogoHeight pixels when
// both are known, with LogoAlt as its alt; ShowAppName is whether the app name is drawn as text.
// Footer is the brand's footer links and support contact, drawn under the card in InkMuted with each
// link in Link, as a page draws them under its card, or nil for a brand with neither, which draws no
// footer (#817 decision 2). Its Panel is not drawn: an email has no background image.
type EmailFrame struct {
	ColorScheme string
	Canvas      string
	Surface     string
	Line        string
	Ink         string
	InkMuted    string
	Link        string
	PanelRadius string
	FontFamily  string
	Logo        string
	LogoWidth   int
	LogoHeight  int
	LogoAlt     string
	ShowAppName bool
	Footer      *PageFooter
}

// The bounds an email's logo is drawn within: as tall as a page's (.auth-logo img, 4rem), and as wide
// as the card's content. A client that ignores a style's bounds, as Outlook on Windows does, draws it
// at its width and height attributes, which hold it to these.
const (
	emailLogoMaxHeight = 64
	emailLogoMaxWidth  = 424
)

// emailPanelRadii are the card's corner for each corner shape, a panel's radius in pixels, since rem
// is not drawn alike by every client: brandkit's for square and pill, and ui.css's --radius-panel,
// 0.75rem, for rounded and for a value that is none of the three.
var emailPanelRadii = map[record.BrandCorners]string{
	record.BrandCornersSquare: "0",
	record.BrandCornersPill:   "24px",
}

const emailRoundedPanelRadius = "12px"

// emailFrameOf answers the frame an email for an app named appName is drawn in ctx in, in brand, its
// logo linked under baseURL, the auth server's public base URL, and its footer in the language of
// ctx's catalog, which the body and the subject are written in too.
//
// A brand that cannot be read is drawn as the built-in look, in Blueberry's light colors, rounded and
// in System UI, with the app name as text (#817, today's page whose brand cannot be read): an email
// is never refused over its look. With no base URL there is no absolute URL to link the logo by, so
// the app name takes its place.
func emailFrameOf(ctx context.Context, appName string, brand PageBrand, baseURL string) EmailFrame {
	look := brand.Email
	colors := look.Colors
	if colors == nil {
		look = EmailLook{}
		colors, _ = brandthemes.ModeColors(&record.Brand{Theme: record.BrandThemeBlueberry}, false)
	}

	frame := EmailFrame{
		ColorScheme: "light",
		Canvas:      colors["canvas"],
		Surface:     colors["surface"],
		Line:        colors["line"],
		Ink:         colors["ink"],
		InkMuted:    colors["ink-muted"],
		Link:        colors["brand"],
		PanelRadius: emailRoundedPanelRadius,
		FontFamily:  emailFontFamily(brandkit.SystemUIStack),
		ShowAppName: true,
		Footer:      FooterOf(ctx, brand),
	}
	if look.Dark {
		frame.ColorScheme = "dark"
	}
	if radius, ok := emailPanelRadii[look.Corners]; ok {
		frame.PanelRadius = radius
	}
	// An uploaded font is a file a page loads, which an email cannot: it is drawn in System UI, as
	// its fallback is.
	if look.Font != record.BrandFontUploaded {
		if stack, ok := brandkit.FontStack(string(look.Font)); ok {
			frame.FontFamily = emailFontFamily(stack)
		}
	}

	// The logo sits above the app name, and its alt is the app name only while the name's text is
	// hidden, so the name is read once and is there with images blocked (#813 decision 5).
	if look.Logo != "" && baseURL != "" {
		frame.Logo = strings.TrimSuffix(baseURL, "/") + look.Logo
		frame.LogoWidth, frame.LogoHeight = fitEmailLogo(look.LogoWidth, look.LogoHeight)
		if brand.HideAppName {
			frame.LogoAlt = appName
			frame.ShowAppName = false
		}
	}
	return frame
}

// emailFontFamily is a font-family list as an email writes it: with its family names unquoted, since
// html/template refuses a quote in a style attribute's value. Every quoted name in brandkit's lists is
// a sequence of identifiers, which CSS's font-family reads as the same family unquoted, and none is a
// generic family's keyword, which unquoting would turn it into.
func emailFontFamily(stack string) string {
	return strings.ReplaceAll(stack, "'", "")
}

// fitEmailLogo answers the size a logo of width by height pixels is drawn at, within the logo's
// bounds and in its proportions, or zero for both when its size is not known.
func fitEmailLogo(width, height int) (int, int) {
	if width <= 0 || height <= 0 {
		return 0, 0
	}
	if height > emailLogoMaxHeight {
		width = max(1, (width*emailLogoMaxHeight+height/2)/height)
		height = emailLogoMaxHeight
	}
	if width > emailLogoMaxWidth {
		height = max(1, (height*emailLogoMaxWidth+width/2)/width)
		width = emailLogoMaxWidth
	}
	return width, height
}
