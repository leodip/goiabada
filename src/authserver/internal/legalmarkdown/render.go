// Package legalmarkdown renders the Markdown of a legal document to HTML, for the admin API's
// preview and the document's public pages alike, so an administrator previews exactly what users
// will read (#622 decision 4). It is the one place in the auth server that turns text into markup a
// page shows as markup: its output is the one template.HTML value the server builds from data, and
// trusted_html_lint_test.go refuses any other.
//
// The text is written by an administrator, so the renderer is not a defence against a hostile
// author holding the admin console; it keeps a document from doing what a document should not do
// even by accident. It renders CommonMark plus GFM tables through goldmark, which is
// CommonMark-compliant, pure Go and has no dependencies of its own:
//
//   - raw HTML, block or inline, is left out (goldmark's default without html.WithUnsafe);
//   - a link to a javascript:, vbscript:, file: or non-image data: address keeps its text and loses
//     its address (goldmark's IsDangerousURL);
//   - an image is never loaded: it is drawn as a link to its address, named by its alternative text,
//     so a document cannot make its readers' browsers call another host.
package legalmarkdown

import (
	"bytes"
	"html/template"

	"github.com/leodip/goiabada/core/errs"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/util"
)

// imagePriority puts imageAsLink ahead of goldmark's own HTML renderer, registered at 1000: the
// renderer with the lower number is registered last and wins the node kind.
const imagePriority = 100

// markdown is the one configured converter. goldmark's Markdown is safe for concurrent use once
// built.
var markdown = goldmark.New(
	goldmark.WithExtensions(extension.Table),
	goldmark.WithRendererOptions(
		renderer.WithNodeRenderers(util.Prioritized(imageAsLink{}, imagePriority)),
	),
)

// Render renders a legal document's Markdown to HTML.
func Render(source string) (template.HTML, error) {
	var out bytes.Buffer
	if err := markdown.Convert([]byte(source), &out); err != nil {
		return "", errs.Wrap(err, "unable to render the legal document's markdown")
	}
	//nolint:gosec // G203: goldmark's output with raw HTML left out, dangerous addresses dropped and images drawn as links; see the package comment.
	return template.HTML(out.String()), nil
}

// imageAsLink draws an image as a link to its address instead of an <img>, so the reader's browser
// fetches nothing until the reader follows it.
type imageAsLink struct{}

func (imageAsLink) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(ast.KindImage, renderImageAsLink)
}

func renderImageAsLink(w util.BufWriter, source []byte, node ast.Node, entering bool) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkContinue, nil
	}
	image := node.(*ast.Image)
	alt := altText(source, image)

	// Inside a link the image is its alternative text: the link around it already goes somewhere,
	// and a link inside a link is not HTML.
	for parent := node.Parent(); parent != nil; parent = parent.Parent() {
		if parent.Kind() == ast.KindLink {
			_, _ = w.Write(util.EscapeHTML(alt))
			return ast.WalkSkipChildren, nil
		}
	}

	// The address is escaped and screened exactly as goldmark's own link renderer does it.
	dest := util.URLEscape(image.Destination, true)
	if html.IsDangerousURL(dest) {
		dest = nil
	}
	if len(alt) == 0 {
		alt = dest
	}
	_, _ = w.WriteString(`<a href="`)
	_, _ = w.Write(util.EscapeHTML(dest))
	_, _ = w.WriteString(`">`)
	_, _ = w.Write(util.EscapeHTML(alt))
	_, _ = w.WriteString(`</a>`)
	return ast.WalkSkipChildren, nil
}

// altText is an image's alternative text, its description with every inline markup taken away, as
// CommonMark section 6.4 says an image's alt attribute is rendered.
func altText(source []byte, node ast.Node) []byte {
	var text []byte
	for child := node.FirstChild(); child != nil; child = child.NextSibling() {
		switch c := child.(type) {
		case *ast.Text:
			// The segment's bytes, as Segment.Value reads them; an inline text segment carries no
			// padding.
			text = append(text, source[c.Segment.Start:c.Segment.Stop]...)
			if c.SoftLineBreak() || c.HardLineBreak() {
				text = append(text, ' ')
			}
		case *ast.String:
			text = append(text, c.Value...)
		default:
			text = append(text, altText(source, child)...)
		}
	}
	return text
}
