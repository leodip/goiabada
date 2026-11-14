package emaildelivery

import (
	"net/url"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"

	"github.com/leodip/goiabada/core/errs"
)

// emailButtonAttr marks the email layout's button: its URL is written under it, so the text gives
// it once (#817 decision 10).
const emailButtonAttr = "data-email-button"

// PlainText works out the plain-text part of an email from the HTML it is sent as (#817 decision
// 10): the body, which is the <main> element or, with none, the whole <body>, then each <footer>
// outside it. A block is a paragraph, a blank line between two, and a <br> breaks a line; bold and
// other inline elements are plain words. A link is its URL, or its label then its URL in angle
// brackets when the two differ, a mailto: or tel: link's URL being its address or number. Images,
// the head, scripts and the button are left out, and with them the logo and the app name above the
// body, which are outside <main>. An email with no text to read is an error: none is sent without
// its text.
//
// The sender sends it beside the HTML, and an email template's preview answers it (#818 decision 11),
// so the preview's plain text is the one a recipient gets.
func PlainText(source string) (string, error) {
	doc, err := html.Parse(strings.NewReader(source))
	if err != nil {
		return "", errs.Wrap(err, "unable to read the email's HTML")
	}

	w := &textWriter{}
	if main := findElement(doc, atom.Main); main != nil {
		w.children(main)
		for _, footer := range findElements(doc, atom.Footer) {
			if !isInside(footer, main) {
				w.block(footer)
			}
		}
	} else {
		w.children(doc)
	}

	text := w.String()
	if text == "" {
		return "", errs.New("the email has no text")
	}
	return text, nil
}

// blockElements are the elements a paragraph starts and ends at.
var blockElements = map[atom.Atom]bool{
	atom.Address: true, atom.Article: true, atom.Aside: true, atom.Blockquote: true, atom.Body: true,
	atom.Center: true, atom.Dd: true, atom.Div: true, atom.Dl: true, atom.Dt: true, atom.Figcaption: true,
	atom.Figure: true, atom.Footer: true, atom.Form: true, atom.H1: true, atom.H2: true, atom.H3: true,
	atom.H4: true, atom.H5: true, atom.H6: true, atom.Header: true, atom.Hr: true, atom.Li: true,
	atom.Main: true, atom.Nav: true, atom.Ol: true, atom.P: true, atom.Pre: true, atom.Section: true,
	atom.Table: true, atom.Tbody: true, atom.Td: true, atom.Tfoot: true, atom.Th: true, atom.Thead: true,
	atom.Tr: true, atom.Ul: true,
}

// skippedElements hold nothing a reader of the text reads.
var skippedElements = map[atom.Atom]bool{
	atom.Head: true, atom.Title: true, atom.Style: true, atom.Script: true, atom.Noscript: true,
	atom.Template: true, atom.Img: true, atom.Picture: true, atom.Svg: true, atom.Iframe: true,
	atom.Object: true, atom.Video: true, atom.Audio: true,
}

// textWriter gathers paragraphs, each a run of lines, collapsing whitespace as a browser does.
type textWriter struct {
	paragraphs []string
	lines      []string
	line       strings.Builder
	// space is whether whitespace was met since the line's last word.
	space bool
}

func (w *textWriter) word(s string) {
	if w.space && w.line.Len() > 0 {
		w.line.WriteByte(' ')
	}
	w.space = false
	w.line.WriteString(s)
}

// text writes s with its runs of HTML whitespace collapsed to one space.
func (w *textWriter) text(s string) {
	start := -1
	for i := 0; i < len(s); i++ {
		if isHTMLSpace(s[i]) {
			if start >= 0 {
				w.word(s[start:i])
				start = -1
			}
			w.space = true
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		w.word(s[start:])
	}
}

func isHTMLSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

func (w *textWriter) breakLine() {
	w.lines = append(w.lines, w.line.String())
	w.line.Reset()
	w.space = false
}

// endParagraph ends the paragraph being written, if it holds anything.
func (w *textWriter) endParagraph() {
	if w.line.Len() > 0 {
		w.breakLine()
	}
	w.line.Reset()
	w.space = false
	// Lines a <br> ended and nothing followed are not kept at the paragraph's end.
	for len(w.lines) > 0 && w.lines[len(w.lines)-1] == "" {
		w.lines = w.lines[:len(w.lines)-1]
	}
	if len(w.lines) > 0 {
		w.paragraphs = append(w.paragraphs, strings.Join(w.lines, "\n"))
	}
	w.lines = nil
}

func (w *textWriter) String() string {
	w.endParagraph()
	if len(w.paragraphs) == 0 {
		return ""
	}
	return strings.Join(w.paragraphs, "\n\n") + "\n"
}

func (w *textWriter) children(n *html.Node) {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		w.node(c)
	}
}

func (w *textWriter) block(n *html.Node) {
	w.endParagraph()
	w.children(n)
	w.endParagraph()
}

func (w *textWriter) node(n *html.Node) {
	switch n.Type {
	case html.TextNode:
		w.text(n.Data)
	case html.DocumentNode:
		w.children(n)
	case html.ElementNode:
		switch {
		case skippedElements[n.DataAtom], hasAttr(n, emailButtonAttr):
		case n.DataAtom == atom.Br:
			w.breakLine()
		case n.DataAtom == atom.A:
			w.link(n)
		case blockElements[n.DataAtom]:
			w.block(n)
		default:
			w.children(n)
		}
	}
}

// link writes a link as its URL, or as its label and its URL when the label is something else.
func (w *textWriter) link(n *html.Node) {
	label := &textWriter{}
	label.children(n)
	labelText := strings.TrimSpace(strings.ReplaceAll(label.String(), "\n", " "))

	href := strings.TrimSpace(attr(n, "href"))
	target := href
	for _, scheme := range []string{"mailto:", "tel:"} {
		if len(href) >= len(scheme) && strings.EqualFold(href[:len(scheme)], scheme) {
			target, _, _ = strings.Cut(href[len(scheme):], "?")
			if unescaped, err := url.PathUnescape(target); err == nil {
				target = unescaped
			}
			// An address or number of only whitespace is none.
			target = strings.TrimSpace(target)
		}
	}

	switch {
	case target == "":
		w.text(labelText)
	case labelText == "" || labelText == target:
		w.word(target)
	default:
		w.text(labelText)
		w.space = true
		w.word("<" + target + ">")
	}
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Namespace == "" && a.Key == key {
			return a.Val
		}
	}
	return ""
}

func hasAttr(n *html.Node, key string) bool {
	for _, a := range n.Attr {
		if a.Namespace == "" && a.Key == key {
			return true
		}
	}
	return false
}

func findElement(n *html.Node, a atom.Atom) *html.Node {
	if found := findElements(n, a); len(found) > 0 {
		return found[0]
	}
	return nil
}

// findElements answers the elements a under n, in document order.
func findElements(n *html.Node, a atom.Atom) []*html.Node {
	var found []*html.Node
	for c := range n.Descendants() {
		if c.Type == html.ElementNode && c.DataAtom == a {
			found = append(found, c)
		}
	}
	return found
}

func isInside(n, ancestor *html.Node) bool {
	for p := n.Parent; p != nil; p = p.Parent {
		if p == ancestor {
			return true
		}
	}
	return false
}
