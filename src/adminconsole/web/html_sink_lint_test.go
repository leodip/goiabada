package web

import (
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

// TestServedPages_HandNoDataToAnHTMLParser holds every page and script this server serves to the
// rule core/guard.AssertNoHTMLSinks carries with its reasoning (#120): no value reaches the document
// through an HTML or JavaScript parser. It covers what #105's check on the redirect URI and web
// origin cells held, both the write and the read side, on every page rather than two.
//
// htmlSinkAllowances names the one site that still does it, by file and line so it does not drift:
// the dialog's own line. Some dialog messages still splice a stored value into markup, kept from
// executing only by the auth server's input validators, until #120 moves them onto the escaping
// markup builder; the line then stays as the audited branch that renders the builder's result. The
// table cells, links, buttons and banners that were listed here write their data as text now, and
// an entry left behind after its site is fixed fails this test.
func TestServedPages_HandNoDataToAnHTMLParser(t *testing.T) {
	guard.AssertNoHTMLSinks(t, htmlSinkAllowances, templateFS, staticFS)
}

var htmlSinkAllowances = []guard.HTMLSinkAllowance{
	{File: "static/utils.js", Text: `document.getElementById(id + "_modalDialogMessage").innerHTML = message;`},
}
