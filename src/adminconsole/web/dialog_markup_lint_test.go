//go:build !race

package web

import (
	"context"
	"regexp"
	"testing"

	"github.com/leodip/goiabada/core/i18n"
)

// The console's rule for its dialog markup builder (#120, decision 1). showModalDialog parses a
// message as HTML only when it is the result of dialogMarkup or dialogMarkupFormat in
// static/utils.js, which escape every value they are handed. What makes that safe is that the
// markup itself comes from nowhere but the catalog, which carries no data. So every call to either
// builder names its markup as literals: dialogMarkup's first argument is an array of quoted strings
// whose template actions are all catalog lookups, the parts the values go between, and
// dialogMarkupFormat's first argument is a quoted client-side catalog key. A builder named any
// other way, aliased or passed along, is refused too, because its arguments can no longer be read.
//
// Beside it, a dialog message names no catalog text carrying markup in any locale outside a
// builder call: not as one plain catalog literal, not as t("key") or tFormat("key", ...), and not
// spliced around a value. showModalDialog shows a message its builders did not build as text, so
// such a message would show its accent span as tags; a message that needs its markup goes through
// the builder, which also escapes the values that join it.
//
// This rule is the console's and lives here rather than in core/guard, since the auth server has no
// builder. It follows the guard shape all the same: a finder, and a reporting half driven through
// guard.Run. The code is read through guard.ReadScripts, the reader core/guard.AssertNoHTMLSinks
// shares, over the same embedded bytes the browser is served: every script, script element, on...
// attribute and javascript: URL, with interpolations read as code and window["dialogMarkup"] read
// as window.dialogMarkup.
//
// The builders are declared in static/utils.js inside the closure that keeps their markup's brand
// private, and exported from it under their own names; that file may name them in a list of bare
// names, { dialogMarkup, dialogMarkupFormat }, which is how a closure hands out what it declares.
// TestUtilsJS_DialogMarkupBrandIsPrivate holds the shape of that closure.

// markupRe matches the start of a tag or an entity, the two things that make a catalog value
// markup rather than text.
var markupRe = regexp.MustCompile(`<[a-zA-Z/!]|&[a-zA-Z#0-9]+;`)

// catalogMarkup reads the real catalogs, in every locale the console ships.
func catalogMarkup(key string) bool {
	for _, tag := range []string{"en", "pt-BR"} {
		ctx := i18n.WithLocale(context.Background(), true, tag)
		if markupRe.MatchString(i18n.Raw(ctx, key)) {
			return true
		}
	}
	return false
}

// TestDialogMessages_MarkupOnlyThroughTheBuilder holds every page and script this server serves to
// the rule above.
func TestDialogMessages_MarkupOnlyThroughTheBuilder(t *testing.T) {
	assertDialogMessages(t, catalogMarkup, templateFS, staticFS)
}
