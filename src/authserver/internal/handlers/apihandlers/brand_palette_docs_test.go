package apihandlers

// A brand's custom palette as the docs describe it, held to the code (#815).
//
// The customize guide is where an administrator learns what Custom offers before choosing it: the
// editor's Colors section by its labels, the 23 colors by the labels and token names the editor and
// the admin API give them, what basic mode works out, and what a contrast warning establishes, with
// the two WCAG 2.2 success criteria its minimums come from (decision 11). Its admin API part names
// the members decision 2 and 5 add. The guide's two older pointers to regenerating the CSS for a
// brand's own colors point at custom palettes instead, and the glossary and the audit log say their
// part and link to the guide rather than repeat it.
//
// It reads files and the English catalog, and nothing else.

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/docsreader"
	"github.com/leodip/goiabada/core/guard"
	"github.com/leodip/goiabada/core/palette"
)

const (
	// brandThemesHead is the customize guide's section on brands and themes, which holds custom
	// palettes.
	brandThemesHead = "## Brands and themes"
	// customPalettesHead is its subsection on custom palettes, and customPalettesAnchor the link to it.
	customPalettesHead   = "### Custom palettes"
	customPalettesAnchor = "#custom-palettes"
	customPalettesLink   = "/guides/customize-and-translate-the-pages/" + customPalettesAnchor
	// contrastWarningsHead is the subsection saying what a warning means.
	contrastWarningsHead = "### Contrast warnings"
	// paletteAPIHead is the subsection on a palette through the admin API.
	paletteAPIHead = "### Custom palettes through the Admin API"
)

// paletteColorLabel is the editor's English label of a color token, as its Colors section shows it.
func paletteColorLabel(token string) string {
	return english("adminconsole.admin_branding.palette.color." + strings.ReplaceAll(token, "-", "_"))
}

// The themes sentence offers Custom after the eight built-in themes, by the editor's name for it,
// and keeps its claim about the built-in themes as decision 11 words it.
func TestBrandPaletteDocs_TheThemesSentenceOffersCustom(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), customizeGuidePage, brandThemesHead,
		[]string{
			"**" + themeName(record.BrandThemeCustom) + "**",
			"[custom palette](" + customPalettesAnchor + ")",
			"text and borders meet WCAG 2.2 AA contrast",
		}, nil)
}

// The custom palettes subsection names the Colors section, its two modes, the four colors basic mode
// is entered with, the columns and Copy colors from by the editor's labels, and says what basic mode
// works out: the other 19 colors at the save, and Blueberry's status colors (decisions 4, 7 and 13).
func TestBrandPaletteDocs_TheGuideNamesTheColorsSection(t *testing.T) {
	var basic []string
	for _, token := range palette.BasicTokens() {
		basic = append(basic, paletteColorLabel(token))
	}
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), customizeGuidePage, customPalettesHead,
		[]string{
			"**" + themeName(record.BrandThemeCustom) + "**",
			brandLabel("palette.title"),
			brandLabel("palette.mode.basic"),
			brandLabel("palette.mode.advanced"),
			brandLabel("palette.copy_label"),
			brandLabel("appearance.light"),
			brandLabel("appearance.dark"),
			brandLabel("appearance.auto"),
			"four colors for each mode: " + boldList(basic) + ".",
			"other 19",
			"all 23",
			"Blueberry's",
			"#contrast-warnings",
		}, nil)
	if len(palette.Tokens()) != 23 || len(palette.BasicTokens()) != 4 {
		t.Errorf("the guide says 23 colors, four of them entered in basic mode, but the code has %d and %d",
			len(palette.Tokens()), len(palette.BasicTokens()))
	}
}

// The custom palettes subsection's table names every one of the 23 colors once, by the label the
// editor gives it and the token name the editor's Advanced mode and the admin API use (decision 7),
// so an administrator can find a color the API names on the page and the other way round.
func TestBrandPaletteDocs_TheGuideTablesEveryColorByLabelAndToken(t *testing.T) {
	text, err := docsreader.Section(filepath.Dir(guard.SourceRoot(t)), customizeGuidePage, customPalettesHead)
	if err != nil {
		t.Fatal(err)
	}
	var table *docsreader.Table
	for _, candidate := range docsreader.Tables(text) {
		if len(candidate.Header) > 0 && candidate.Header[0] == "Color" {
			table = &candidate
			break
		}
	}
	if table == nil {
		t.Fatalf("%s: %s has no table whose first column is Color", customizeGuidePage, customPalettesHead)
	}
	rows, err := table.Columns("Color", "Token")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, row := range rows {
		seen[row[1]]++
		token := strings.Trim(row[1], "`")
		if want := "**" + paletteColorLabel(token) + "**"; row[0] != want {
			t.Errorf("%s: the row for %s names the color %s, but the editor labels it %s", customizeGuidePage, row[1], row[0], want)
		}
	}
	for _, token := range palette.Tokens() {
		if seen["`"+token+"`"] != 1 {
			t.Errorf("%s: the colors table has %d rows for `%s`, not one", customizeGuidePage, seen["`"+token+"`"], token)
		}
	}
	if len(rows) != len(palette.Tokens()) {
		t.Errorf("%s: the colors table has %d rows, but a palette has %d colors", customizeGuidePage, len(rows), len(palette.Tokens()))
	}
}

// The contrast warnings subsection says what the check establishes and nothing more (decision 11):
// the 35 pairs of each mode, the two minimums and the WCAG 2.2 success criteria they come from, that every built-in theme meets
// them, that a failing pair never stops a save, where the warnings are listed, which modes are
// checked (decision 8), and that passing is no claim that the pages meet WCAG.
func TestBrandPaletteDocs_TheGuideSaysWhatAWarningMeans(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), customizeGuidePage, contrastWarningsHead,
		[]string{
			"35 pairs in each mode",
			"4.5:1",
			"3:1",
			"[1.4.3 Contrast (Minimum)](https://www.w3.org/TR/WCAG22/#contrast-minimum)",
			"[1.4.11 Non-text Contrast](https://www.w3.org/TR/WCAG22/#non-text-contrast)",
			"Every built-in theme meets them",
			"never stops a save",
			"brand list",
			"doesn't meet WCAG 2.2 level AA contrast",
			"Only the modes the brand's appearance draws are checked",
			"doesn't make your pages meet WCAG 2.2 AA",
		},
		[]string{"palette meets WCAG", "is accessible"})
	if n := len(palette.Pairs()); n != 35 {
		t.Errorf("the guide says 35 pairs in each mode, but the shared list holds %d", n)
	}
	if palette.TextMinimum != 4.5 || palette.NonTextMinimum != 3 {
		t.Errorf("the guide states 4.5:1 for text and 3:1 for boundaries and focus rings, but the code's minimums are %v and %v",
			palette.TextMinimum, palette.NonTextMinimum)
	}
}

// The guide warns that a palette nobody can read draws the admin console unreadable too when it is
// the console's brand, and names the way back (decision 12).
func TestBrandPaletteDocs_TheGuideWarnsAboutAnUnreadableConsole(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), customizeGuidePage, contrastWarningsHead,
		[]string{"brand editor included", "(/reference/api/admin/operations/updatebrand/)", "/concepts/clients/#the-admin-consoles-client"}, nil)
}

// The admin API subsection names the members decisions 2 and 5 add: the theme custom and palette
// with its mode and its two modes' maps, the four names basic mode takes, a color's one form, the
// read-only colors and contrastWarnings with an item's members, a ratio cut and never rounded up,
// and a refusal's error_field pointer.
func TestBrandPaletteDocs_TheGuideGivesTheAPIsMembers(t *testing.T) {
	basic := palette.BasicTokens()
	for i, token := range basic {
		basic[i] = "`" + token + "`"
	}
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), customizeGuidePage, paletteAPIHead,
		[]string{
			"`" + record.BrandThemeCustom + "`",
			"`palette`",
			"`mode`",
			"`" + string(record.BrandPaletteModeBasic) + "`",
			"`" + string(record.BrandPaletteModeAdvanced) + "`",
			"`light`",
			"`dark`",
			"exactly " + strings.Join(basic[:3], ", ") + " and " + basic[3] + ".",
			"`#` and six hexadecimal digits",
			"lower case",
			"`colors`",
			"`contrastWarnings`",
			"`foreground`",
			"`background`",
			"`ratio`",
			"`minimum`",
			"`[]`",
			"`null`",
			"never rounded up",
			"`error_field`",
			"`/palette/light/brand`",
			"(/reference/api/admin/operations/getbrandthemes/)",
			"(/reference/api/admin/operations/updatebrand/)",
			`"theme": "custom"`,
		}, nil)
}

// The brands paragraph's admin API sentence says every brand answer carries colors and
// contrastWarnings, and points at the subsection for writing a palette.
func TestBrandPaletteDocs_TheBrandsParagraphNamesTheNewMembers(t *testing.T) {
	text, err := docsreader.Section(filepath.Dir(guard.SourceRoot(t)), customizeGuidePage, brandThemesHead)
	if err != nil {
		t.Fatal(err)
	}
	intro, _, _ := strings.Cut(text, "\n### ")
	for _, want := range []string{"`colors`", "`contrastWarnings`", "#custom-palettes-through-the-admin-api"} {
		if !strings.Contains(intro, want) {
			t.Errorf("%s: %s's paragraphs before its subsections do not say %q", customizeGuidePage, brandThemesHead, want)
		}
	}
}

// The two places that sent an administrator to regenerate the CSS for their own colors send them to
// custom palettes instead (Assumed: "Regenerate the CSS" stays): step 2 of Brand the pages, and the
// colors paragraph of Regenerate the CSS.
func TestBrandPaletteDocs_TheOwnColorsPointersLeadToCustomPalettes(t *testing.T) {
	root := filepath.Dir(guard.SourceRoot(t))
	guard.AssertSectionSays(t, root, customizeGuidePage, "## Brand the pages",
		[]string{"[custom palette](" + customPalettesAnchor + ")"},
		[]string{"[Regenerate the CSS](#regenerate-the-css) to use your own colors"})
	guard.AssertSectionSays(t, root, customizeGuidePage, "## Regenerate the CSS",
		[]string{"[custom palette](" + customPalettesAnchor + ")"},
		[]string{"Change them there and regenerate"})
}

// The glossary's brand has a theme that is a built-in one or a custom palette, and points at the
// guide for it.
func TestBrandPaletteDocs_TheGlossarysBrandHoldsACustomPalette(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), glossaryPage, "### Brand",
		[]string{"custom palette", customPalettesLink},
		[]string{"a theme, one of eight built-in palettes,"})
}

// The audit log's two brand writes say they record a custom palette's mode, and the detail says no
// color is recorded (decision 2), so an auditor knows what to look for and what is not there.
func TestBrandPaletteDocs_TheAuditLogsBrandEventsNameThePalettesMode(t *testing.T) {
	for _, event := range []string{audit.EventCreatedBrand, audit.EventUpdatedBrand} {
		row := auditEventRow(t, "### Brands", event)
		if row == nil {
			t.Errorf("%s: ### Brands has no row for `%s`", auditLogDocsPage, event)
			continue
		}
		if joined := strings.Join(row, " | "); !strings.Contains(joined, "custom palette's mode") {
			t.Errorf("%s: the row for `%s` does not say %q: %s", auditLogDocsPage, event, "custom palette's mode", joined)
		}
	}
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), auditLogDocsPage, "",
		[]string{"| `palette_mode` |", "No color is recorded.", "`custom` for a brand on its own palette"}, nil)
}
