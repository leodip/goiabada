package legalmarkdown

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The renderer's rules, each driven with a document an administrator could write and checked
// against the HTML written out by hand from the CommonMark spec (0.31.2) and the GFM tables
// extension, never against another renderer's output.

func render(t *testing.T, markdown string) string {
	t.Helper()
	html, err := Render(markdown)
	require.NoError(t, err)
	return string(html)
}

func TestRender_CommonMarkBlocksAndInlines(t *testing.T) {
	got := render(t, "# Privacy notice\n\nWe keep **your email** and *your name*.\n\n- one\n- two\n\n1. first\n2. second\n\n> quoted\n\n`code` and [our site](https://example.com/privacy).\n")
	assert.Equal(t, "<h1>Privacy notice</h1>\n"+
		"<p>We keep <strong>your email</strong> and <em>your name</em>.</p>\n"+
		"<ul>\n<li>one</li>\n<li>two</li>\n</ul>\n"+
		"<ol>\n<li>first</li>\n<li>second</li>\n</ol>\n"+
		"<blockquote>\n<p>quoted</p>\n</blockquote>\n"+
		"<p><code>code</code> and <a href=\"https://example.com/privacy\">our site</a>.</p>\n", got)
}

func TestRender_Tables(t *testing.T) {
	got := render(t, "| Data | Kept for |\n|---|---|\n| Email | 2 years |\n")
	assert.Equal(t, "<table>\n<thead>\n<tr>\n<th>Data</th>\n<th>Kept for</th>\n</tr>\n</thead>\n"+
		"<tbody>\n<tr>\n<td>Email</td>\n<td>2 years</td>\n</tr>\n</tbody>\n</table>\n", got)
}

func TestRender_TextIsEscaped(t *testing.T) {
	assert.Equal(t, "<p>Terms &amp; conditions: 1 &lt; 2 and &quot;quoted&quot;</p>\n",
		render(t, "Terms & conditions: 1 < 2 and \"quoted\"\n"))
}

func TestRender_RawHTMLIsLeftOut(t *testing.T) {
	for name, markdown := range map[string]string{
		"a script block":       "<script>alert(1)</script>\n",
		"an inline element":    "Hello <b onclick=\"alert(1)\">there</b>\n",
		"an iframe":            "<iframe src=\"https://tracker.example/\"></iframe>\n",
		"an image element":     "<img src=\"https://tracker.example/pixel.gif\">\n",
		"a style element":      "<style>body{display:none}</style>\n",
		"an event in a div":    "<div onmouseover=\"alert(1)\">x</div>\n",
		"a comment smuggling":  "<!-- --><script>alert(1)</script>\n",
		"an inline anchor tag": "see <a href=\"javascript:alert(1)\">this</a>\n",
	} {
		t.Run(name, func(t *testing.T) {
			got := strings.ToLower(render(t, markdown))
			for _, banned := range []string{"<script", "<b ", "<b>", "<iframe", "<img", "<style", "<div", "onclick", "onmouseover", "javascript:", "<a "} {
				assert.NotContains(t, got, banned)
			}
		})
	}
}

func TestRender_DangerousLinksAreDropped(t *testing.T) {
	for name, markdown := range map[string]string{
		"javascript":     "[click](javascript:alert(1))\n",
		"vbscript":       "[click](vbscript:msgbox)\n",
		"file":           "[click](file:///etc/passwd)\n",
		"data text/html": "[click](data:text/html;base64,PHNjcmlwdD4=)\n",
		"autolink":       "<javascript:alert(1)>\n",
	} {
		t.Run(name, func(t *testing.T) {
			// The text stays, as text; the address is gone.
			got := strings.ToLower(render(t, markdown))
			assert.Contains(t, got, `<a href="">`)
			assert.Equal(t, 1, strings.Count(got, "href="))
		})
	}
	assert.Equal(t, "<p><a href=\"\">click</a></p>\n", render(t, "[click](javascript:alert(1))\n"))
}

func TestRender_SafeLinksAreKept(t *testing.T) {
	assert.Equal(t, "<p><a href=\"mailto:dpo@example.com\">write to us</a></p>\n",
		render(t, "[write to us](mailto:dpo@example.com)\n"))
	assert.Equal(t, "<p><a href=\"/legal/terms\">terms</a></p>\n", render(t, "[terms](/legal/terms)\n"))
}

func TestRender_ImagesAreLinksAndNeverLoaded(t *testing.T) {
	assert.Equal(t, "<p><a href=\"https://cdn.example/logo.png\">Our logo</a></p>\n",
		render(t, "![Our logo](https://cdn.example/logo.png)\n"))
	// With no alternative text the link names the address, so it is never an empty link.
	assert.Equal(t, "<p><a href=\"https://cdn.example/pixel.gif\">https://cdn.example/pixel.gif</a></p>\n",
		render(t, "![](https://cdn.example/pixel.gif)\n"))
	// A reference-style image is an image too.
	assert.Equal(t, "<p><a href=\"https://cdn.example/a.png\">chart</a></p>\n",
		render(t, "![chart][c]\n\n[c]: https://cdn.example/a.png\n"))
	// The alternative text is text: markup in it is escaped, not run.
	assert.Equal(t, "<p><a href=\"https://cdn.example/a.png\">a &amp; b</a></p>\n",
		render(t, "![a & b](https://cdn.example/a.png)\n"))
	// An image address no link may carry is dropped like a link's.
	assert.Equal(t, "<p><a href=\"\">x</a></p>\n", render(t, "![x](javascript:alert(1))\n"))

	// An image inside a link is its alternative text: the link around it already goes somewhere,
	// and a link inside a link is not HTML.
	assert.Equal(t, "<p>Intro <a href=\"https://a.example/1.png\">a</a> and <a href=\"https://c.example/\">b</a></p>\n",
		render(t, "Intro ![a](https://a.example/1.png) and [![b](https://b.example/2.png)](https://c.example/)\n"))
}

func TestRender_EmptyDocumentIsEmpty(t *testing.T) {
	assert.Empty(t, render(t, ""))
}
