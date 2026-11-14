package emailtemplate

// The format an email's text is written in (#818 decisions 2, 3, 5 and 17), and the one place it
// becomes markup: Render's body is the auth server's second template.HTML built from data, beside a
// legal document's, which legalmarkdown's trusted_html_lint_test.go holds to these two files.
//
// The body is a small Markdown set: paragraphs, line breaks (a single newline is one), bold,
// italic, links, and bulleted and numbered lists, parsed by goldmark with every other block and
// inline parser left out, so a heading, a block quote, a table, code, an image or raw HTML is shown
// as the characters typed, escaped, and is never refused. The body is not drawn by goldmark's HTML
// renderer but by renderBody, which writes only the elements of the set, every link in the brand's
// color, inline, and a link to an address other than the web, mail or a phone number as its text
// alone. A placeholder is an inline node of its own, written {{name}}, whose value is written as
// text, escaped, and never read as Markdown or HTML; \{{ writes the two braces.
//
// The text is written by an administrator, so the format is not a defence against a hostile author
// holding the admin console; it keeps an email from doing what an email should not, even by
// accident: loading an image, running anything, or handing the action link to another site.

import (
	"bufio"
	"bytes"
	"fmt"
	"html/template"
	"regexp"
	"strconv"
	"strings"

	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/parser"
	gmhtml "github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/inputvalidation"
)

// Field names a field of a Text, as a refusal names the field it is about.
type Field string

const (
	FieldSubject     Field = "subject"
	FieldButtonLabel Field = "button_label"
	FieldBody        Field = "body"
)

// Rule names a rule of the format that a text breaks (#818 decisions 3 and 17).
type Rule string

const (
	// RuleUnknownPlaceholder is a placeholder whose name the email does not offer.
	RuleUnknownPlaceholder Rule = "unknown_placeholder"
	// RuleRequiredPlaceholderMissing is a placeholder the email requires that its body does not
	// draw. {{button}} does not draw the link: the plain-text part leaves the button out.
	RuleRequiredPlaceholderMissing Rule = "required_placeholder_missing"
	// RulePlaceholderNotInSubject is {{link}} or {{button}} in the subject, which takes text values
	// only.
	RulePlaceholderNotInSubject Rule = "placeholder_not_in_subject"
	// RuleButtonNotAlone is {{button}} that is not alone on its line.
	RuleButtonNotAlone Rule = "button_not_alone"
	// RulePlaceholderInLinkDestination is a placeholder in a link's destination other than {{link}}
	// as the whole of it, which would hand the link to another site.
	RulePlaceholderInLinkDestination Rule = "placeholder_in_link_destination"
	// RuleNothingToRead is a body that is empty once {{button}} is left out, which in a brand with no
	// footer could never be sent, the sender refusing a message with no text.
	RuleNothingToRead Rule = "nothing_to_read"
)

// The limits of a text's fields (#818 decision 7), each counted in inputvalidation.TextLength's
// unit, as a legal document's are.
const (
	// RuleEmpty is a subject, or the button label of an email with a button, that is empty or
	// blank. An empty body is RuleNothingToRead.
	RuleEmpty Rule = "empty"
	// RuleTooLong is a field longer than its limit: record.EmailTemplateSubjectMaxLength,
	// record.EmailTemplateButtonLabelMaxLength or record.EmailTemplateBodyMaxLength.
	RuleTooLong Rule = "too_long"
	// RuleNotOneLine is a subject holding a line break.
	RuleNotOneLine Rule = "not_one_line"
	// RuleNoButton is a button label for an email that has no button.
	RuleNoButton Rule = "no_button"
)

// Problem is one rule a text breaks: the field it is in, the rule, and the placeholder it is
// about, as written between the braces, for a rule about one. The email's placeholders are what a
// refusal lists as what it offers.
type Problem struct {
	Field       Field
	Rule        Rule
	Placeholder string
}

// Problems are the rules a text breaks, in the order of its fields and of where each is met. As an
// error it is the refusal a save gives; it names rules and placeholders, never the text.
type Problems []Problem

func (p Problems) Error() string {
	parts := make([]string, len(p))
	for i, problem := range p {
		parts[i] = string(problem.Field) + ": " + string(problem.Rule)
		if problem.Placeholder != "" {
			parts[i] += " (" + problem.Placeholder + ")"
		}
	}
	return "the email's text breaks the format's rules: " + strings.Join(parts, "; ")
}

// Broken answers each problem as its field and its rule, such as "body: unknown_placeholder", for a
// log record. Unlike Error it leaves the placeholder out, since its name is whatever was typed
// between the braces, and a log record never holds an email's text.
func (p Problems) Broken() []string {
	broken := make([]string, len(p))
	for i, problem := range p {
		broken[i] = string(problem.Field) + ": " + string(problem.Rule)
	}
	return broken
}

// Look is what a body takes from the frame it is drawn in (render.EmailFrame): the brand's color a
// link and the button are drawn in, the color of the button's label on it, the button's corner and
// font, and the boxed code's background, border, corner, ink and monospace font. The values are
// written into style attributes as they are, so Render refuses any that is not a #rrggbb color, a
// length in pixels, or a list of font family names written unquoted.
type Look struct {
	Link, OnBrand, ControlRadius, FontFamily string
	Subtle, Line, BoxRadius, Ink, CodeFamily string
}

var (
	lookColor  = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
	lookRadius = regexp.MustCompile(`^(0|[0-9]+px)$`)
	lookFamily = regexp.MustCompile(`^[A-Za-z0-9 ,-]+$`)
)

func (l Look) check() error {
	for _, color := range []string{l.Link, l.OnBrand, l.Subtle, l.Line, l.Ink} {
		if !lookColor.MatchString(color) {
			return errs.Errorf("the email's look has a color that is not #rrggbb: %q", color)
		}
	}
	for _, radius := range []string{l.ControlRadius, l.BoxRadius} {
		if !lookRadius.MatchString(radius) {
			return errs.Errorf("the email's look has a corner that is not a length in pixels: %q", radius)
		}
	}
	for _, family := range []string{l.FontFamily, l.CodeFamily} {
		if !lookFamily.MatchString(family) {
			return errs.Errorf("the email's look has a font list that is not unquoted family names: %q", family)
		}
	}
	return nil
}

// Rendered is a text rendered with its values: the subject, plain text, and the body as the HTML
// the email layout draws inside its frame.
type Rendered struct {
	Subject string
	Body    template.HTML
}

// Check answers the rules text breaks as this email's, nil for none. It is the check a save, a
// preview, a test send and the read of a stored edit make alike, and depends on nothing but the
// text: not the values, nor the brand.
func (e *Email) Check(text Text) Problems {
	problems := e.checkSubject(text.Subject)
	problems = append(problems, e.checkButtonLabel(text.ButtonLabel)...)
	if inputvalidation.TextLength(text.Body) > record.EmailTemplateBodyMaxLength {
		problems = append(problems, Problem{Field: FieldBody, Rule: RuleTooLong})
	}
	_, bodyProblems := e.body(text.Body, nil)
	return append(problems, bodyProblems...)
}

// checkButtonLabel answers the rules a button label breaks (#818 decisions 5 and 7): for an email
// with a button, one that is blank or past its limit; for one without, any label at all. A label is
// plain text, so nothing in it is a placeholder.
func (e *Email) checkButtonLabel(label string) Problems {
	switch {
	case !e.HasButton():
		if label != "" {
			return Problems{{Field: FieldButtonLabel, Rule: RuleNoButton}}
		}
	case strings.TrimSpace(label) == "":
		return Problems{{Field: FieldButtonLabel, Rule: RuleEmpty}}
	case inputvalidation.TextLength(label) > record.EmailTemplateButtonLabelMaxLength:
		return Problems{{Field: FieldButtonLabel, Rule: RuleTooLong}}
	}
	return nil
}

// Render renders text, written in lang, one of Languages, with values, in look. A text Check would
// refuse is refused with those Problems, and nothing is rendered.
func (e *Email) Render(lang string, text Text, values Values, look Look) (Rendered, error) {
	if err := look.check(); err != nil {
		return Rendered{}, err
	}
	if problems := e.Check(text); len(problems) > 0 {
		return Rendered{}, problems
	}
	r := &bodyRenderer{
		look: look, buttonLabel: text.ButtonLabel, link: values.Link,
		values: map[string]string{
			AppName:   values.AppName,
			Name:      values.Name,
			Link:      values.Link,
			Code:      values.Code,
			Expiry:    expiryIn(lang, values.Expiry),
			CodesLeft: strconv.Itoa(values.CodesLeft),
		},
	}
	body, _ := e.body(text.Body, r)
	return Rendered{
		Subject: substitute(text.Subject, r.values),
		//nolint:gosec // G203: the body drawn by renderBody, every text and value escaped, every link screened; see the file's comment.
		Body: template.HTML(body),
	}, nil
}

// checkSubject answers the rules a subject breaks: blank, past its limit or on more than one line
// (#818 decision 7), a placeholder the email does not offer, and the link or the button, which a
// subject cannot draw.
func (e *Email) checkSubject(subject string) Problems {
	var problems Problems
	switch {
	case strings.TrimSpace(subject) == "":
		problems = append(problems, Problem{Field: FieldSubject, Rule: RuleEmpty})
	case inputvalidation.TextLength(subject) > record.EmailTemplateSubjectMaxLength:
		problems = append(problems, Problem{Field: FieldSubject, Rule: RuleTooLong})
	}
	if strings.ContainsAny(subject, "\r\n") {
		problems = append(problems, Problem{Field: FieldSubject, Rule: RuleNotOneLine})
	}
	for _, found := range placeholdersIn(subject, false) {
		p, offered := e.placeholder(found)
		switch {
		case !offered:
			problems = append(problems, Problem{Field: FieldSubject, Rule: RuleUnknownPlaceholder, Placeholder: found})
		case !p.InSubject():
			problems = append(problems, Problem{Field: FieldSubject, Rule: RulePlaceholderNotInSubject, Placeholder: found})
		}
	}
	return problems
}

// placeholderSyntax is a placeholder as written in a subject or a link's destination: two braces,
// a name with no brace or line break, two braces. Its name is what is between them, spaces and
// tabs trimmed.
var placeholderSyntax = regexp.MustCompile(`\{\{([^{}\n]*)\}\}`)

// placeholdersIn answers the names of the placeholders written in s, in order. A placeholder whose
// braces follow a backslash is escaped and is not one; markdown says whether s is Markdown, where a
// backslash escapes a backslash, so one after an even run of them still is.
func placeholdersIn(s string, markdown bool) []string {
	var names []string
	for _, match := range placeholderSyntax.FindAllStringSubmatchIndex(s, -1) {
		if escapedAt(s, match[0], markdown) {
			continue
		}
		names = append(names, placeholderName(s[match[2]:match[3]]))
	}
	return names
}

// escapedAt reports whether the braces at i follow an escaping backslash.
func escapedAt(s string, i int, markdown bool) bool {
	backslashes := 0
	for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
		backslashes++
		if !markdown {
			break
		}
	}
	return backslashes%2 == 1
}

func placeholderName(inner string) string {
	return strings.Trim(inner, " \t")
}

// substitute writes a subject with each placeholder's value and each \{{ as the two braces. The
// subject is plain text, a header the sender encodes, so nothing is escaped.
func substitute(subject string, values map[string]string) string {
	var out strings.Builder
	last := 0
	for _, match := range placeholderSyntax.FindAllStringSubmatchIndex(subject, -1) {
		if escapedAt(subject, match[0], false) {
			out.WriteString(subject[last : match[0]-1])
			out.WriteString(subject[match[0]:match[1]])
		} else {
			out.WriteString(subject[last:match[0]])
			out.WriteString(values[placeholderName(subject[match[2]:match[3]])])
		}
		last = match[1]
	}
	out.WriteString(subject[last:])
	return out.String()
}

// buttonLine is a line holding {{button}} alone, which is drawn as a block of its own.
var buttonLine = regexp.MustCompile(`(?m)^[ \t]*\{\{[ \t]*button[ \t]*\}\}[ \t]*$`)

// markdown is the parser of the Markdown set: lists and paragraphs, and links, emphasis and
// placeholders inline. Link reference definitions are left out with the rest, so a link's
// destination is always written beside it, where the destination rule reads it.
var markdown = parser.NewParser(
	parser.WithBlockParsers(
		util.Prioritized(parser.NewListParser(), 300),
		util.Prioritized(parser.NewListItemParser(), 400),
		util.Prioritized(parser.NewParagraphParser(), 1000),
	),
	parser.WithInlineParsers(
		util.Prioritized(parser.NewLinkParser(), 200),
		util.Prioritized(parser.NewEmphasisParser(), 500),
		util.Prioritized(placeholderParser{}, 600),
	),
)

// body parses a body and walks it, answering the rules it breaks and, with r, its HTML. Every line
// holding {{button}} alone becomes a paragraph of its own before it is parsed, so the button is
// never inside a sentence, a list or an emphasis that a line break would otherwise carry across.
func (e *Email) body(source string, r *bodyRenderer) (string, Problems) {
	source = strings.ReplaceAll(strings.ReplaceAll(source, "\r\n", "\n"), "\r", "\n")
	var problems Problems

	isolated := []byte(buttonLine.ReplaceAllString(source, "\n{{button}}\n"))
	document := markdown.Parse(text.NewReader(isolated))
	w := &bodyWalker{email: e, source: isolated, r: r, used: map[string]bool{}}
	var out bytes.Buffer
	w.out = bufio.NewWriter(&out)
	w.blocks(document)
	_ = w.out.Flush()
	problems = append(problems, w.problems...)

	for _, p := range e.Placeholders {
		if p.Required && !w.used[p.Name] {
			problems = append(problems, Problem{Field: FieldBody, Rule: RuleRequiredPlaceholderMissing, Placeholder: p.Name})
		}
	}
	if strings.TrimSpace(buttonLine.ReplaceAllString(source, "")) == "" {
		problems = append(problems, Problem{Field: FieldBody, Rule: RuleNothingToRead})
	}
	return out.String(), problems
}

// bodyRenderer is what a body is drawn with: the values, the button's label and link, and the
// look. A walk without one checks the body and draws nothing anyone reads.
type bodyRenderer struct {
	look        Look
	buttonLabel string
	link        string
	values      map[string]string
}

// bodyWalker walks a parsed body, writing the elements of the set and gathering the problems it
// meets and the placeholders it draws.
type bodyWalker struct {
	email    *Email
	source   []byte
	r        *bodyRenderer
	out      *bufio.Writer
	problems Problems
	used     map[string]bool
	// inLink is how many links the walk is inside; a link inside a link's text is its text.
	inLink int
}

func (w *bodyWalker) write(s string) { _, _ = w.out.WriteString(s) }

func (w *bodyWalker) escaped(s string) { _, _ = w.out.Write(util.EscapeHTML([]byte(s))) }

func (w *bodyWalker) value(name string) string {
	if w.r == nil {
		return ""
	}
	return w.r.values[name]
}

func (w *bodyWalker) problem(rule Rule, placeholder string) {
	w.problems = append(w.problems, Problem{Field: FieldBody, Rule: rule, Placeholder: placeholder})
}

// blocks writes the blocks under n.
func (w *bodyWalker) blocks(n ast.Node) {
	for child := n.FirstChild(); child != nil; child = child.NextSibling() {
		switch block := child.(type) {
		case *ast.Paragraph:
			w.paragraph(block)
		case *ast.List:
			w.list(block)
		case *ast.TextBlock:
			// A tight list item's text, written without a paragraph around it.
			w.inlines(block)
			if block.NextSibling() != nil {
				w.write("\n")
			}
		default:
			w.blocks(child)
		}
	}
}

// soleChild answers the placeholder that is the whole of a paragraph, if one is.
func soleChild(paragraph *ast.Paragraph) (*placeholderNode, bool) {
	if paragraph.ChildCount() != 1 {
		return nil, false
	}
	node, ok := paragraph.FirstChild().(*placeholderNode)
	return node, ok
}

func (w *bodyWalker) paragraph(paragraph *ast.Paragraph) {
	if node, ok := soleChild(paragraph); ok {
		if _, offered := w.email.placeholder(node.name); offered {
			switch {
			case node.name == Button && paragraph.Parent().Kind() == ast.KindDocument:
				w.button()
				return
			case node.name == Code:
				w.used[Code] = true
				w.code()
				return
			}
		}
	}
	w.write("<p>")
	w.inlines(paragraph)
	w.write("</p>\n")
}

func (w *bodyWalker) list(list *ast.List) {
	tag := "ul"
	if list.IsOrdered() {
		tag = "ol"
	}
	w.write("<" + tag)
	if list.IsOrdered() && list.Start != 1 {
		w.write(` start="` + strconv.Itoa(list.Start) + `"`)
	}
	w.write(">\n")
	for item := list.FirstChild(); item != nil; item = item.NextSibling() {
		w.write("<li>")
		if _, tight := item.FirstChild().(*ast.TextBlock); !tight && item.FirstChild() != nil {
			w.write("\n")
		}
		w.blocks(item)
		w.write("</li>\n")
	}
	w.write("</" + tag + ">\n")
}

// inlines writes the inline content under n.
func (w *bodyWalker) inlines(n ast.Node) {
	for child := n.FirstChild(); child != nil; child = child.NextSibling() {
		w.inline(child)
	}
}

func (w *bodyWalker) inline(n ast.Node) {
	switch node := n.(type) {
	case *ast.Text:
		// The segment's bytes, as Segment.Value reads them; an inline text segment carries no
		// padding.
		w.text(w.source[node.Segment.Start:node.Segment.Stop], node.IsRaw())
		if node.SoftLineBreak() || node.HardLineBreak() {
			w.write("<br>\n")
		}
	case *ast.String:
		w.text(node.Value, node.IsRaw() || node.IsCode())
	case *ast.Emphasis:
		tag := "em"
		if node.Level == 2 {
			tag = "strong"
		}
		w.write("<" + tag + ">")
		w.inlines(node)
		w.write("</" + tag + ">")
	case *ast.Link:
		w.link(node)
	case *ast.Image:
		w.imageAsTyped(node)
	case *placeholderNode:
		w.placeholder(node)
	default:
		w.inlines(n)
	}
}

// text writes a piece of the source as goldmark writes text: backslash escapes and entity
// references resolved, then escaped, or, raw, only escaped.
func (w *bodyWalker) text(value []byte, raw bool) {
	if raw {
		gmhtml.DefaultWriter.RawWrite(w.out, value)
		return
	}
	gmhtml.DefaultWriter.Write(w.out, value)
}

func (w *bodyWalker) placeholder(node *placeholderNode) {
	if _, offered := w.email.placeholder(node.name); !offered {
		w.problem(RuleUnknownPlaceholder, node.name)
		return
	}
	switch node.name {
	case Button:
		// A button inside a sentence, a list or anything but a paragraph of its own.
		w.problem(RuleButtonNotAlone, Button)
	case Link:
		w.used[Link] = true
		if w.inLink > 0 {
			w.escaped(w.value(Link))
			return
		}
		w.anchor(w.value(Link))
		w.escaped(w.value(Link))
		w.write("</a>")
	default:
		w.used[node.name] = true
		w.escaped(w.value(node.name))
	}
}

// anchor opens a link to href, in the brand's color.
func (w *bodyWalker) anchor(href string) {
	color := ""
	if w.r != nil {
		color = w.r.look.Link
	}
	w.write(`<a href="`)
	w.escaped(href)
	w.write(`" style="color: ` + color + `;">`)
}

// allowedSchemes are the addresses a link of a body may lead to: the web, mail and a phone number.
// A link to any other, javascript:, data:, a file or an address with no scheme, which in an email
// resolves against nothing, keeps its text and loses its address.
var allowedSchemes = []string{"https://", "http://", "mailto:", "tel:"}

func (w *bodyWalker) link(link *ast.Link) {
	destination := string(link.Destination)
	href := ""
	switch names := placeholdersIn(destination, true); {
	case len(names) == 0:
		escaped := string(util.URLEscape(link.Destination, true))
		for _, scheme := range allowedSchemes {
			if len(escaped) >= len(scheme) && strings.EqualFold(escaped[:len(scheme)], scheme) {
				href = escaped
				break
			}
		}
	case len(names) == 1 && names[0] == Link && placeholderSyntax.FindString(destination) == destination:
		if _, offered := w.email.placeholder(Link); !offered {
			w.problem(RuleUnknownPlaceholder, Link)
			break
		}
		w.used[Link] = true
		href = w.value(Link)
	default:
		w.problem(RulePlaceholderInLinkDestination, names[0])
	}

	if href == "" || w.inLink > 0 {
		w.inLink++
		w.inlines(link)
		w.inLink--
		return
	}
	w.inLink++
	w.anchor(href)
	w.inlines(link)
	w.write("</a>")
	w.inLink--
}

// imageAsTyped writes an image as the characters typed: no image is loaded.
func (w *bodyWalker) imageAsTyped(image *ast.Image) {
	w.write("![")
	w.inlines(image)
	w.write("](")
	w.escaped(string(image.Destination))
	if image.Title != nil {
		w.write(` &quot;`)
		w.escaped(string(image.Title))
		w.write(`&quot;`)
	}
	w.write(")")
}

// button writes the brand's button to the link, labelled with the button label, which is plain
// text: the brand's color on the cell, as bgcolor too, since a client that drops a link's padding
// still paints the cell, and on the link, the label in the color drawn on the brand's, rounded as a
// page's button is. data-email-button tells the sender to leave the button out of the plain-text
// part, whose URL the body writes beside it.
func (w *bodyWalker) button() {
	if w.r == nil {
		return
	}
	l := w.r.look
	w.write(`<table role="presentation" data-email-button cellpadding="0" cellspacing="0" border="0" style="margin: 0 0 16px; border-collapse: separate;">` + "\n")
	w.write("<tr>\n")
	w.write(fmt.Sprintf(`<td align="center" bgcolor="%s" style="background-color: %s; border-radius: %s;">`, l.Link, l.Link, l.ControlRadius) + "\n")
	w.write(`<a href="`)
	w.escaped(w.r.link)
	w.write(fmt.Sprintf(`" style="display: inline-block; padding: 12px 24px; border: 1px solid %s; border-radius: %s; `+
		`background-color: %s; color: %s; font-family: %s; font-size: 16px; font-weight: 600; line-height: 24px; text-decoration: none;">`,
		l.Link, l.ControlRadius, l.Link, l.OnBrand, l.FontFamily))
	w.escaped(w.r.buttonLabel)
	w.write("</a>\n</td>\n</tr>\n</table>\n")
}

// code writes the code set apart in a box of its own, larger than the text and in a monospace face.
func (w *bodyWalker) code() {
	if w.r == nil {
		return
	}
	l := w.r.look
	w.write(fmt.Sprintf(`<p style="margin: 0 0 16px; padding: 12px 16px; background-color: %s; border: 1px solid %s; `+
		`border-radius: %s; color: %s; font-family: %s; font-size: 28px; font-weight: 600; letter-spacing: 4px; `+
		`line-height: 36px; text-align: center;">`, l.Subtle, l.Line, l.BoxRadius, l.Ink, l.CodeFamily))
	w.escaped(w.value(Code))
	w.write("</p>\n")
}

// kindPlaceholder is the kind of a placeholder's node.
var kindPlaceholder = ast.NewNodeKind("EmailPlaceholder")

// placeholderNode is a placeholder written in a body's text, by its name.
type placeholderNode struct {
	ast.BaseInline
	name string
}

func (n *placeholderNode) Kind() ast.NodeKind { return kindPlaceholder }

func (n *placeholderNode) Dump(source []byte, level int) {
	ast.DumpHelper(n, source, level, map[string]string{"Name": n.name}, nil)
}

// placeholderParser reads {{name}} in a body's text into a placeholderNode. A backslash before the
// braces escapes the first, as it escapes any punctuation, so \{{ is never read as one.
type placeholderParser struct{}

func (placeholderParser) Trigger() []byte { return []byte{'{'} }

func (placeholderParser) Parse(_ ast.Node, block text.Reader, _ parser.Context) ast.Node {
	line, _ := block.PeekLine()
	match := placeholderSyntax.FindSubmatchIndex(line)
	if match == nil || match[0] != 0 {
		return nil
	}
	block.Advance(match[1])
	return &placeholderNode{name: placeholderName(string(line[match[2]:match[3]]))}
}
