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
// htmlSinkAllowances names the one site that still does it, by file and text so it does not drift:
// the dialog's markup branch, which renders what dialogMarkup or dialogMarkupFormat built, whose
// markup is the catalog's and whose values are escaped. It is the one audited exception. The
// dialog's plain branch shows its message as text, and the table cells, links, buttons and banners
// that were listed here write their data as text; an entry left behind after its site is fixed
// fails this test.
func TestServedPages_HandNoDataToAnHTMLParser(t *testing.T) {
	guard.AssertNoHTMLSinks(t, htmlSinkAllowances, templateFS, staticFS)
}

var htmlSinkAllowances = []guard.HTMLSinkAllowance{
	{File: "static/utils.js", Text: `messageElement.innerHTML = message.html;`},
}
