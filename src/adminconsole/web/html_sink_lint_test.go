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
// htmlSinkAllowances names the sites that still do it, by file and line so they do not drift: the
// dialog's two branches. The first renders what dialogMarkup or dialogMarkupFormat built, whose
// markup is the catalog's and whose values are escaped, and stays as the one audited exception. The
// second still parses a plain message, because some messages splice a stored value into markup,
// kept from executing only by the auth server's input validators, until #120 moves them onto the
// builder and shows a plain message as text. The table cells, links, buttons and banners that were
// listed here write their data as text now, and an entry left behind after its site is fixed fails
// this test.
func TestServedPages_HandNoDataToAnHTMLParser(t *testing.T) {
	guard.AssertNoHTMLSinks(t, htmlSinkAllowances, templateFS, staticFS)
}

var htmlSinkAllowances = []guard.HTMLSinkAllowance{
	{File: "static/utils.js", Text: `messageElement.innerHTML = message.html;`},
	{File: "static/utils.js", Text: `messageElement.innerHTML = message;`},
}
