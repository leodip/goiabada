package web

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The preview's second view, Messages (#815 decision 10): a switch on the preview's heading line
// shows, in the sample of the mode shown, either the sign-in card with the brand's footer under it,
// or the Messages card, which holds the tones and states the sign-in card does not draw. The switch
// is there whatever the theme and the appearance, so the pane has one layout, and the samples keep
// being drawn in the theme the form holds, whichever view shows.

// statusTokens are the eleven status colors of a palette, as ui.css names them.
var statusTokens = []string{
	"danger", "danger-strong", "on-danger", "danger-soft", "danger-ink",
	"positive-soft", "positive-ink", "caution-soft", "caution-ink", "note-soft", "note-ink",
}

// assertView holds the shown sample of a look to one view: the other drawn hidden, and the footer,
// which belongs to the sign-in page, hidden under the Messages card.
func assertView(t *testing.T, look previewLook, mode, view, msg string) {
	t.Helper()
	sample := look.Samples[mode]
	assert.False(t, sample.Hidden, "%s: the %s sample shows", msg, mode)
	assert.Equal(t, map[string]bool{"signin": view != "signin", "messages": view != "messages"}, sample.Views, "%s: the %s sample's views", msg, mode)
	if view == "messages" {
		assert.True(t, sample.Footer.Hidden, "%s: no footer under the Messages card", msg)
	}
}

// The page starts on the sign-in view, and the switch shows the Messages view in place of it, and
// the sign-in view back, its footer with it; the mode and the theme picked meanwhile keep the view,
// each sample still drawn in its own mode of the theme.
func TestBrandPreviewJS_TheViewSwitchShowsTheMessagesView(t *testing.T) {
	page := previewPage{themeCards: bothCards, theme: "blueberry", appearance: "auto",
		footer: map[string]string{"supportEmail": "help@example.com"}}
	looks := runBrandPreview(t, page,
		load(), lookAt(),
		pick("brandPreviewView", "messages"), lookAt(),
		pick("brandPreviewMode", "dark"), lookAt(),
		pick("theme", "plum"), lookAt(),
		pick("brandPreviewView", "signin"), lookAt())

	assertView(t, looks[0], "light", "signin", "on load")
	assert.False(t, looks[0].Samples["light"].Footer.Hidden, "the footer under the sign-in card")
	assert.Equal(t, "signin", looks[0].PreviewView)

	assertView(t, looks[1], "light", "messages", "Messages picked")
	assert.True(t, looks[1].Samples["dark"].Hidden, "the dark sample stays hidden")
	assertSampleDrawn(t, looks[1].Samples["light"], previewBlueberry.Light, "light")

	assertView(t, looks[2], "dark", "messages", "Dark picked")
	assert.True(t, looks[2].Samples["light"].Hidden)
	assertSampleDrawn(t, looks[2].Samples["dark"], previewBlueberry.Dark, "dark")

	assertView(t, looks[3], "dark", "messages", "Plum picked")
	assertSampleDrawn(t, looks[3].Samples["dark"], previewPlum.Dark, "dark")

	assertView(t, looks[4], "dark", "signin", "Sign-in picked again")
	assert.False(t, looks[4].Samples["dark"].Footer.Hidden, "the footer is back under the sign-in card")
	for i, look := range looks {
		assert.False(t, look.ViewSwitchHidden, "look %d: the view switch shows", i)
		assert.Empty(t, look.StyledElsewhere, "look %d: only the samples are styled", i)
	}
}

// The switch is there under every appearance, the Light/Dark switch hidden under Light and Dark,
// and the view it is on shows in the one sample the appearance decides; it is not the mode switch,
// so picking a view under Automatic leaves the mode where it is.
func TestBrandPreviewJS_TheViewSwitchIsThereUnderEveryAppearance(t *testing.T) {
	for _, appearance := range []string{"auto", "light", "dark"} {
		t.Run(appearance, func(t *testing.T) {
			looks := runBrandPreview(t, previewPage{themeCards: bothCards, theme: "plum", appearance: appearance},
				load(), pick("brandPreviewView", "messages"), lookAt(),
				pick("appearance", "dark"), lookAt(), pick("appearance", "light"), lookAt())

			mode := map[string]string{"auto": "light", "light": "light", "dark": "dark"}[appearance]
			assertView(t, looks[0], mode, "messages", appearance)
			assert.False(t, looks[0].ViewSwitchHidden)
			assert.Equal(t, appearance != "auto", looks[0].SwitchHidden, "the Light/Dark switch")
			assert.Equal(t, "light", looks[0].PreviewMode, "the mode switch is left where it is")
			assertView(t, looks[1], "dark", "messages", "Dark picked")
			assertView(t, looks[2], "light", "messages", "Light picked")
			for i, look := range looks {
				assert.False(t, look.ViewSwitchHidden, "look %d: the view switch shows", i)
			}
		})
	}
}

// On Custom, each status color typed is drawn at once in the sample of its mode, which the
// Messages view keeps showing: the switch follows the edited field's mode and not the view.
func TestBrandPreviewJS_TheMessagesViewFollowsEachStatusColor(t *testing.T) {
	for _, mode := range []string{"light", "dark"} {
		for i, token := range statusTokens {
			t.Run(mode+"/"+token, func(t *testing.T) {
				value := fmt.Sprintf("#5a7%s%02d", map[string]string{"light": "1", "dark": "2"}[mode], i)
				looks := runBrandPreview(t, customPreview("auto"),
					load(), pick("brandPreviewView", "messages"),
					typeIn("palette-"+mode+"-"+token, value), lookAt())

				assertView(t, looks[0], mode, "messages", "after "+token)
				assert.Equal(t, value, looks[0].Samples[mode].Style["--color-"+token])
				assert.Equal(t, "messages", looks[0].PreviewView)
			})
		}
	}
}

// A browser restoring the form, as on Back, fires no input: the view it restores the switch to is
// shown on pageshow.
func TestBrandPreviewJS_PageshowShowsTheRestoredView(t *testing.T) {
	looks := runBrandPreview(t, previewPage{themeCards: bothCards, theme: "blueberry", appearance: "auto"},
		load(), restore("brandPreviewView", "messages"), lookAt(),
		previewStep{Do: "pageshow", Persisted: true}, lookAt())

	assertView(t, looks[0], "light", "signin", "nothing is drawn before pageshow")
	assertView(t, looks[1], "light", "messages", "after pageshow")
}
