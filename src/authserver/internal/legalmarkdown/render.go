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
//     so a document cannot make its readers' browsers call another host;
//   - its headings sit under the page's own: every page that shows a document has a heading of
//     its own, its one <h1>, so the document's highest heading level is rendered as <h2> and the
//     rest move down with it, keeping their order (docs/development/ui.md: one <h1>, no skipped
//     level). A level past 6 stays at 6.
package legalmarkdown

import (
	"bufio"
	"bytes"
	"html/template"

	"github.com/leodip/goiabada/core/errs"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

// imagePriority puts imageAsLink ahead of goldmark's own HTML renderer, registered at 1000: the
// renderer with the lower number is registered last and wins the node kind.
const imagePriority = 100

// markdown is the one configured converter. goldmark's Markdown is safe for concurrent use once
// built.
var markdown = goldmark.New(
	goldmark.WithExtensions(extension.Table),
	goldmark.WithParserOptions(
		parser.WithASTTransformers(util.Prioritized(headingsUnderThePage{}, headingsPriority)),
	),
	goldmark.WithRendererOptions(
		renderer.WithNodeRenderers(util.Prioritized(imageAsLink{}, imagePriority)),
	),
)

// headingsPriority orders headingsUnderThePage among the parser's AST transformers; it is the only
// one, so any priority does.
const headingsPriority = 100

// pageHeadingLevel is the level of the heading the page showing a document gives it; the
// document's own headings start one below.
const pageHeadingLevel = 1

// headingsUnderThePage moves the document's headings down so that its highest level is the one
// below the page's heading, keeping how far apart they are.
type headingsUnderThePage struct{}

func (headingsUnderThePage) Transform(document *ast.Document, _ text.Reader, _ parser.Context) {
	var headings []*ast.Heading
	_ = ast.Walk(document, func(node ast.Node, entering bool) (ast.WalkStatus, error) {
		if heading, ok := node.(*ast.Heading); ok && entering {
			headings = append(headings, heading)
		}
		return ast.WalkContinue, nil
	})
	if len(headings) == 0 {
		return
	}
	highest := headings[0].Level
	for _, heading := range headings {
		highest = min(highest, heading.Level)
	}
	shift := pageHeadingLevel + 1 - highest
	for _, heading := range headings {
		heading.Level = min(heading.Level+shift, 6)
	}
}

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
	alt := altHTML(source, image)

	// Inside a link the image is its alternative text: the link around it already goes somewhere,
	// and a link inside a link is not HTML.
	for parent := node.Parent(); parent != nil; parent = parent.Parent() {
		if parent.Kind() == ast.KindLink {
			_, _ = w.Write(alt)
			return ast.WalkSkipChildren, nil
		}
	}

	// The address is escaped and screened exactly as goldmark's own link renderer does it.
	dest := util.URLEscape(image.Destination, true)
	if html.IsDangerousURL(dest) {
		dest = nil
	}
	if len(alt) == 0 {
		alt = util.EscapeHTML(dest)
	}
	_, _ = w.WriteString(`<a href="`)
	_, _ = w.Write(util.EscapeHTML(dest))
	_, _ = w.WriteString(`">`)
	_, _ = w.Write(alt)
	_, _ = w.WriteString(`</a>`)
	return ast.WalkSkipChildren, nil
}

// altHTML is an image's alternative text as HTML text, its description with every inline markup
// taken away, as CommonMark section 6.4 says an image's alt attribute is rendered. Each piece of
// text is written as goldmark's own renderer writes it (html.Writer): backslash escapes and entity
// references resolved, then escaped once, and a code span's text taken literally (sections 2.4, 2.5
// and 6.1).
func altHTML(source []byte, image *ast.Image) []byte {
	var out bytes.Buffer
	buffered := bufio.NewWriter(&out)
	writeAltText(buffered, source, image, false)
	_ = buffered.Flush()
	return out.Bytes()
}

// writeAltText writes the text under node; raw is whether it lies inside a code span.
func writeAltText(w util.BufWriter, source []byte, node ast.Node, raw bool) {
	for child := node.FirstChild(); child != nil; child = child.NextSibling() {
		switch c := child.(type) {
		case *ast.Text:
			// The segment's bytes, as Segment.Value reads them; an inline text segment carries
			// no padding.
			value := source[c.Segment.Start:c.Segment.Stop]
			if raw || c.IsRaw() {
				html.DefaultWriter.RawWrite(w, value)
			} else {
				html.DefaultWriter.Write(w, value)
			}
			if c.SoftLineBreak() || c.HardLineBreak() {
				_ = w.WriteByte(' ')
			}
		case *ast.String:
			switch {
			case c.IsCode():
				_, _ = w.Write(c.Value)
			case raw || c.IsRaw():
				html.DefaultWriter.RawWrite(w, c.Value)
			default:
				html.DefaultWriter.Write(w, c.Value)
			}
		case *ast.CodeSpan:
			writeAltText(w, source, c, true)
		default:
			writeAltText(w, source, child, raw)
		}
	}
}
