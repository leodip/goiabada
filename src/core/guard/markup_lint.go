package guard

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"text/template/parse"
)

// AssertWellFormedTemplates holds every page template under root in fsys to well-formed HTML and to
// the accessibility rules a template can be held to without rendering it (#617). It reads each
// template's parse tree, so every branch of every {{if}}, {{with}} and {{range}} is checked, and an
// action stands for the text, attribute or value it renders.
//
// Markup:
//   - every element is closed explicitly and in order, a void element never is, and none is closed
//     by a trailing slash outside SVG;
//   - an element opened in a branch closes in that branch, so a template reads the same whichever
//     branch runs;
//   - attribute values are quoted, and no attribute appears twice on an element;
//   - none of the nesting a browser repairs silently: a block element in a <p>, a form in a form, a
//     link or button in a link or button, a list item outside a list, stray content in a table;
//   - no executable script: an inline <script> is a JSON data block, <script type="application/json">,
//     whose body is valid JSON with each action read as a value, or loads a file with src and has no
//     body; no on... attribute and no javascript: URL.
//
// Accessibility:
//   - every form control has a label: a <label for> naming its id, a <label> around it, or
//     aria-label or aria-labelledby;
//   - every <img> has alt, every <svg> is hidden from assistive technology or named, and every link
//     and button has a name: text, an action, or aria-label or aria-labelledby;
//   - at most one <h1> per file, heading levels never skip on the way down, <html> has lang, and no
//     tabindex is positive;
//   - every id that for, aria-labelledby or aria-describedby names is declared in the same file, and
//     an id written without an action is neither repeated inside {{range}} nor declared twice.
//
// outOfScope names the files no rule reads, a path or a directory ending in "/": the email
// templates, which are not pages. pending names the pages not yet brought under the rules, which
// are read and must still fail: one that passes is reported, so the list only shrinks.
func AssertWellFormedTemplates(t *testing.T, fsys fs.FS, root string, outOfScope, pending []string) {
	t.Helper()

	assertWellFormedTemplates(t, fsys, root, outOfScope, pending)
}

// assertWellFormedTemplates is the reporting half, failing through a Reporter so a rule test can
// drive it against a fixture FS. See Reporter in guard.go.
func assertWellFormedTemplates(r Reporter, fsys fs.FS, root string, outOfScope, pending []string) {
	r.Helper()

	seen := map[string]bool{}
	checked := 0
	walkOrFail(r, fsys, root, func(path, content string) {
		rel := strings.TrimPrefix(path, root+"/")
		seen[rel] = true
		if matchesTemplateList(rel, outOfScope) {
			return
		}
		found := findMarkupProblems(path, content)
		if listsTemplate(rel, pending) {
			if len(found) == 0 {
				r.Errorf("%s: listed as pending, and already meets every rule; remove it from the list", path)
			}
			return
		}
		checked++
		for _, f := range found {
			r.Errorf("%s: %s", f.path, f.detail)
		}
	})
	for _, entry := range append(append([]string{}, outOfScope...), pending...) {
		if !strings.HasSuffix(entry, "/") && !seen[entry] {
			r.Errorf("%s/%s: listed, and no such template exists; remove it from the list", root, entry)
		}
	}
	if checked == 0 {
		r.Fatalf("every .html file under %s is out of scope or pending; this guard is checking nothing", root)
	}
}

func matchesTemplateList(rel string, list []string) bool {
	for _, entry := range list {
		if rel == entry || (strings.HasSuffix(entry, "/") && strings.HasPrefix(rel, entry)) {
			return true
		}
	}
	return false
}

func listsTemplate(rel string, list []string) bool {
	for _, entry := range list {
		if rel == entry {
			return true
		}
	}
	return false
}

// findMarkupProblems returns one finding per rule a template breaks, each naming its line.
func findMarkupProblems(path, content string) []templateFinding {
	tree := parse.New(path)
	tree.Mode = parse.SkipFuncCheck | parse.ParseComments
	set := map[string]*parse.Tree{}
	if _, err := tree.Parse(content, "", "", set); err != nil {
		return []templateFinding{{path: path, detail: "does not parse: " + err.Error()}}
	}

	c := &markupChecker{lines: newlineOffsets(content), staticIDs: map[string]int{}}
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		t := set[name]
		if t.Root == nil {
			continue
		}
		s := &markupState{}
		c.walkList(s, t.Root)
		c.finishTree(s)
	}
	c.finishFile()

	sort.SliceStable(c.found, func(i, j int) bool { return c.found[i].line < c.found[j].line })
	out := make([]templateFinding, 0, len(c.found))
	for _, f := range c.found {
		out = append(out, templateFinding{path: path, detail: fmt.Sprintf("line %d: %s", f.line, f.message)})
	}
	return out
}

func newlineOffsets(content string) []int {
	var offsets []int
	for i := 0; i < len(content); i++ {
		if content[i] == '\n' {
			offsets = append(offsets, i)
		}
	}
	return offsets
}

type markupFinding struct {
	line    int
	message string
}

type markupMode int

const (
	modeText markupMode = iota
	modeTagOpen
	modeTagName
	modeTag
	modeAttrName
	modeAfterAttrName
	modeBeforeValue
	modeValue
	modeValueUnquoted
	modeSelfClosing
	modeComment
	modeDeclaration
	modeRawText
)

// hole stands for an action in a value read as JSON: a value whatever the action renders.
const hole = "null"

type markupAttr struct {
	name    string
	value   string // as written, each action spelled as the parser prints it
	dynamic bool   // the value holds an action
}

type markupTag struct {
	name      string
	end       bool
	line      int
	attrs     []markupAttr
	dynamic   bool // an action stands among the attributes, so any of them may be present
	selfClose bool
	attrName  string
	attrValue strings.Builder
	valueDyn  bool
}

func (t *markupTag) clone() *markupTag {
	if t == nil {
		return nil
	}
	n := &markupTag{name: t.name, end: t.end, line: t.line, dynamic: t.dynamic, selfClose: t.selfClose,
		attrName: t.attrName, valueDyn: t.valueDyn}
	n.attrs = append(n.attrs, t.attrs...)
	n.attrValue.WriteString(t.attrValue.String())
	return n
}

func (t *markupTag) attr(name string) (markupAttr, bool) {
	for _, a := range t.attrs {
		if a.name == name {
			return a, true
		}
	}
	return markupAttr{}, false
}

func (t *markupTag) has(name string) bool {
	_, ok := t.attr(name)
	return ok
}

type openElement struct {
	name    string
	line    int
	foreign bool
	named   bool // it holds text, an action or a named image, or carries a name of its own
	script  string
}

type markupState struct {
	mode    markupMode
	quote   byte
	tag     *markupTag
	stack   []openElement
	raw     strings.Builder
	branch  int
	ranges  int
	heading int
}

func (s *markupState) clone() *markupState {
	n := &markupState{mode: s.mode, quote: s.quote, tag: s.tag.clone(), branch: s.branch, ranges: s.ranges, heading: s.heading}
	n.stack = append(n.stack, s.stack...)
	n.raw.WriteString(s.raw.String())
	return n
}

func (s *markupState) top() *openElement {
	if len(s.stack) == 0 {
		return nil
	}
	return &s.stack[len(s.stack)-1]
}

func (s *markupState) within(names ...string) bool {
	for i := range s.stack {
		for _, n := range names {
			if s.stack[i].name == n {
				return true
			}
		}
	}
	return false
}

func (s *markupState) foreign() bool {
	top := s.top()
	return top != nil && (top.foreign || top.name == "svg" || top.name == "math")
}

// markName marks every open element as holding content a name can come from.
func (s *markupState) markName() {
	for i := range s.stack {
		s.stack[i].named = true
	}
}

type markupControl struct {
	id   string
	line int
}

type markupRef struct {
	attr string
	id   string
	line int
}

type markupChecker struct {
	lines     []int
	found     []markupFinding
	ids       map[string]bool
	staticIDs map[string]int
	labelFor  map[string]bool
	controls  []markupControl
	refs      []markupRef
	h1        []int
}

func (c *markupChecker) line(pos int) int {
	return sort.SearchInts(c.lines, pos) + 1
}

func (c *markupChecker) report(line int, format string, args ...any) {
	c.found = append(c.found, markupFinding{line: line, message: fmt.Sprintf(format, args...)})
}

func (c *markupChecker) walkList(s *markupState, list *parse.ListNode) {
	if list == nil {
		return
	}
	for _, node := range list.Nodes {
		c.walkNode(s, node)
	}
}

func (c *markupChecker) walkNode(s *markupState, node parse.Node) {
	switch n := node.(type) {
	case *parse.TextNode:
		c.text(s, string(n.Text), int(n.Pos))
	case *parse.ActionNode:
		if n.Pipe != nil && (len(n.Pipe.Decl) > 0 || n.Pipe.IsAssign) {
			return // a declaration or an assignment renders nothing
		}
		c.action(s, n.String(), int(n.Pos))
	case *parse.TemplateNode:
		c.action(s, n.String(), int(n.Pos))
	case *parse.IfNode:
		c.branches(s, int(n.Pos), false, n.List, n.ElseList)
	case *parse.WithNode:
		c.branches(s, int(n.Pos), false, n.List, n.ElseList)
	case *parse.RangeNode:
		c.branches(s, int(n.Pos), true, n.List, n.ElseList)
	case *parse.ListNode:
		c.walkList(s, n)
	}
}

// branches walks each branch from the state before it, and requires each to end in that state:
// what a branch opens, it closes. The state after is the state before, holding what any branch
// added to it: an attribute, or content that names an element still open.
func (c *markupChecker) branches(s *markupState, pos int, isRange bool, body, otherwise *parse.ListNode) {
	c.settle(s)
	before := s.clone()
	var ends []*markupState
	for i, list := range []*parse.ListNode{body, otherwise} {
		b := before.clone()
		b.branch++
		if isRange && i == 0 {
			b.ranges++
		}
		c.walkList(b, list)
		c.settle(b)
		ends = append(ends, b)
	}
	for _, b := range ends {
		if !sameShape(before, b) {
			c.report(c.line(pos), "a branch ends %s, where it began %s: what a branch opens it closes, "+
				"so the page reads the same whichever branch runs", describeShape(b), describeShape(before))
		}
	}
	for _, b := range ends {
		if len(b.stack) == len(s.stack) {
			for i := range s.stack {
				s.stack[i].named = s.stack[i].named || b.stack[i].named
			}
		}
		if s.tag != nil && b.tag != nil {
			s.tag.dynamic = s.tag.dynamic || b.tag.dynamic
			for _, a := range b.tag.attrs {
				if !s.tag.has(a.name) {
					s.tag.attrs = append(s.tag.attrs, a)
				}
			}
		}
		if b.heading > s.heading {
			s.heading = b.heading
		}
	}
}

// settle completes an attribute name in progress: an attribute written alone in a branch, such
// as {{if .checked}}checked{{end}}, ends where the branch does.
func (c *markupChecker) settle(s *markupState) {
	if s.mode == modeTagName {
		s.mode = modeTag
	}
	if s.mode == modeAttrName || s.mode == modeAfterAttrName {
		c.commitAttr(s)
		s.mode = modeTag
	}
}

func sameShape(a, b *markupState) bool {
	if a.mode != b.mode || a.quote != b.quote || len(a.stack) != len(b.stack) {
		return false
	}
	for i := range a.stack {
		if a.stack[i].name != b.stack[i].name {
			return false
		}
	}
	return (a.tag == nil) == (b.tag == nil)
}

func describeShape(s *markupState) string {
	where := "in text"
	switch s.mode {
	case modeText:
	case modeValue, modeValueUnquoted, modeBeforeValue:
		where = "inside an attribute value"
	case modeComment:
		where = "inside a comment"
	case modeRawText:
		where = "inside a <" + s.top().name + ">"
	default:
		where = "inside a tag"
	}
	names := make([]string, 0, len(s.stack))
	for _, e := range s.stack {
		names = append(names, "<"+e.name+">")
	}
	if len(names) == 0 {
		return where + " with no element open"
	}
	return where + " with " + strings.Join(names, " ") + " open"
}

func (c *markupChecker) action(s *markupState, spelled string, pos int) {
	switch s.mode {
	case modeText:
		s.markName()
	case modeTagOpen:
		c.report(c.line(pos), "an action writes a tag's name; write the name")
		s.tag = &markupTag{name: "?", line: c.line(pos)}
		s.mode = modeTagName
	case modeTagName, modeTag, modeAfterAttrName, modeSelfClosing:
		if s.mode == modeAfterAttrName {
			c.commitAttr(s)
		}
		s.tag.dynamic = true
		s.mode = modeTag
	case modeAttrName:
		s.tag.attrName += spelled
	case modeBeforeValue, modeValueUnquoted:
		c.report(c.line(pos), "attribute %s is not quoted: write %s=\"%s\"", s.tag.attrName, s.tag.attrName, spelled)
		s.tag.attrValue.WriteString(spelled)
		s.tag.valueDyn = true
		s.mode = modeValueUnquoted
	case modeValue:
		s.tag.attrValue.WriteString(spelled)
		s.tag.valueDyn = true
	case modeRawText:
		s.raw.WriteString(hole)
	case modeComment, modeDeclaration:
	}
}

func (c *markupChecker) text(s *markupState, text string, base int) {
	for i := 0; i < len(text); i++ {
		ch := text[i]
		pos := base + i
		switch s.mode {
		case modeText:
			switch {
			case ch == '<':
				s.mode = modeTagOpen
			case !isMarkupSpace(ch):
				s.markName()
				if top := s.top(); top != nil && !top.foreign && textForbiddenIn[top.name] {
					c.report(c.line(pos), "text directly in a <%s>, which a browser moves out of it", top.name)
				}
			}
		case modeTagOpen:
			switch {
			case ch == '!':
				if strings.HasPrefix(text[i:], "!--") {
					s.mode = modeComment
					i += 2
				} else {
					s.mode = modeDeclaration
				}
			case ch == '/':
				s.tag = &markupTag{end: true, line: c.line(pos)}
				s.mode = modeTagName
			case isNameStart(ch):
				s.tag = &markupTag{name: string(ch), line: c.line(pos)}
				s.mode = modeTagName
			default:
				c.report(c.line(pos), "a bare < in text: write &lt;")
				s.mode = modeText
				i--
			}
		case modeTagName:
			switch {
			case isMarkupSpace(ch):
				s.mode = modeTag
			case ch == '>':
				c.finishTag(s)
			case ch == '/':
				s.mode = modeSelfClosing
			default:
				s.tag.name += string(ch)
			}
		case modeTag:
			switch {
			case isMarkupSpace(ch):
			case ch == '>':
				c.finishTag(s)
			case ch == '/':
				s.mode = modeSelfClosing
			default:
				s.tag.attrName = string(ch)
				s.mode = modeAttrName
			}
		case modeAttrName:
			switch {
			case isMarkupSpace(ch):
				s.mode = modeAfterAttrName
			case ch == '=':
				s.mode = modeBeforeValue
			case ch == '>':
				c.commitAttr(s)
				c.finishTag(s)
			case ch == '/':
				c.commitAttr(s)
				s.mode = modeSelfClosing
			default:
				s.tag.attrName += string(ch)
			}
		case modeAfterAttrName:
			switch {
			case isMarkupSpace(ch):
			case ch == '=':
				s.mode = modeBeforeValue
			case ch == '>':
				c.commitAttr(s)
				c.finishTag(s)
			case ch == '/':
				c.commitAttr(s)
				s.mode = modeSelfClosing
			default:
				c.commitAttr(s)
				s.tag.attrName = string(ch)
				s.mode = modeAttrName
			}
		case modeBeforeValue:
			switch {
			case isMarkupSpace(ch):
			case ch == '"' || ch == '\'':
				s.quote = ch
				s.mode = modeValue
			case ch == '>':
				c.report(c.line(pos), "attribute %s has an = and no value", s.tag.attrName)
				c.commitAttr(s)
				c.finishTag(s)
			default:
				c.report(c.line(pos), "attribute %s is not quoted", s.tag.attrName)
				s.tag.attrValue.WriteByte(ch)
				s.mode = modeValueUnquoted
			}
		case modeValue:
			if ch == s.quote {
				c.commitAttr(s)
				s.quote = 0
				s.mode = modeTag
			} else {
				s.tag.attrValue.WriteByte(ch)
			}
		case modeValueUnquoted:
			switch {
			case isMarkupSpace(ch):
				c.commitAttr(s)
				s.mode = modeTag
			case ch == '>':
				c.commitAttr(s)
				c.finishTag(s)
			default:
				s.tag.attrValue.WriteByte(ch)
			}
		case modeSelfClosing:
			if ch == '>' {
				s.tag.selfClose = true
				c.finishTag(s)
			} else if !isMarkupSpace(ch) {
				s.mode = modeTag
				i--
			}
		case modeComment:
			if strings.HasPrefix(text[i:], "-->") {
				s.mode = modeText
				i += 2
			}
		case modeDeclaration:
			if ch == '>' {
				s.mode = modeText
			}
		case modeRawText:
			name := s.top().name
			rest := strings.ToLower(text[i:])
			at := strings.Index(rest, "</"+name)
			if at < 0 {
				s.raw.WriteString(text[i:])
				return
			}
			s.raw.WriteString(text[i : i+at])
			c.closeRawText(s)
			s.tag = &markupTag{end: true, line: c.line(base + i + at)}
			s.mode = modeTagName
			i += at + 1
		}
	}
}

func (c *markupChecker) commitAttr(s *markupState) {
	t := s.tag
	name := strings.ToLower(t.attrName)
	value := t.attrValue.String()
	if name != "" {
		if t.has(name) {
			c.report(t.line, "<%s> carries %s twice", t.name, name)
		} else {
			t.attrs = append(t.attrs, markupAttr{name: name, value: value, dynamic: t.valueDyn})
		}
	}
	t.attrName = ""
	t.attrValue.Reset()
	t.valueDyn = false
}

func (c *markupChecker) finishTag(s *markupState) {
	t := s.tag
	s.tag = nil
	s.mode = modeText
	if t == nil {
		return
	}
	foreign := s.foreign()
	if !foreign {
		t.name = strings.ToLower(t.name)
	}
	if t.end {
		c.closeElement(s, t)
		return
	}
	c.startElement(s, t, foreign)
}

var voidElements = map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true, "hr": true, "img": true,
	"input": true, "link": true, "meta": true, "source": true, "track": true, "wbr": true,
}

var blockElements = map[string]bool{
	"address": true, "article": true, "aside": true, "blockquote": true, "details": true, "dialog": true,
	"div": true, "dl": true, "fieldset": true, "figcaption": true, "figure": true, "footer": true,
	"form": true, "h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true, "header": true,
	"hgroup": true, "hr": true, "main": true, "menu": true, "nav": true, "ol": true, "p": true, "pre": true,
	"section": true, "table": true, "ul": true,
}

var rawTextElements = map[string]bool{"script": true, "style": true, "textarea": true, "title": true}

// textForbiddenIn names the elements whose content is elements alone.
var textForbiddenIn = map[string]bool{
	"table": true, "thead": true, "tbody": true, "tfoot": true, "tr": true, "ul": true, "ol": true,
	"select": true, "colgroup": true,
}

// tableChildren names the children each table part allows, besides the script-supporting ones.
var tableChildren = map[string]map[string]bool{
	"table": {"caption": true, "colgroup": true, "thead": true, "tbody": true, "tfoot": true, "tr": true},
	"thead": {"tr": true},
	"tbody": {"tr": true},
	"tfoot": {"tr": true},
	"tr":    {"td": true, "th": true},
}

var unlabelledInputTypes = map[string]bool{"hidden": true, "submit": true, "button": true, "reset": true, "image": true}

var headingLevel = map[string]int{"h1": 1, "h2": 2, "h3": 3, "h4": 4, "h5": 5, "h6": 6}

var jsonScriptType = regexp.MustCompile(`^application/(ld\+)?json$`)

func (c *markupChecker) startElement(s *markupState, t *markupTag, foreign bool) {
	name, line := t.name, t.line
	parent := s.top()

	for _, a := range t.attrs {
		if strings.HasPrefix(a.name, "on") && len(a.name) > 2 {
			c.report(line, "<%s> carries %s: register the handler from a static script", name, a.name)
		}
		switch a.name {
		case "href", "src", "action", "formaction", "xlink:href":
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(a.value)), "javascript:") {
				c.report(line, "<%s %s> is a javascript: URL: register the behaviour from a static script", name, a.name)
			}
		case "tabindex":
			if n, err := strconv.Atoi(strings.TrimSpace(a.value)); err == nil && n > 0 {
				c.report(line, "<%s> has tabindex %d: a positive tabindex reorders the keyboard path", name, n)
			}
		case "id":
			c.declareID(s, a, line)
		case "aria-labelledby", "aria-describedby":
			for _, id := range strings.Fields(a.value) {
				c.refs = append(c.refs, markupRef{attr: a.name, id: id, line: line})
			}
		case "for":
			if name == "label" {
				if c.labelFor == nil {
					c.labelFor = map[string]bool{}
				}
				c.labelFor[a.value] = true
				c.refs = append(c.refs, markupRef{attr: "for", id: a.value, line: line})
			}
		}
	}

	if foreign {
		if t.selfClose {
			return
		}
		s.stack = append(s.stack, openElement{name: name, line: line, foreign: true})
		return
	}

	if t.selfClose {
		if voidElements[name] {
			c.report(line, "<%s/>: write a void element without the trailing slash", name)
		} else if name != "svg" && name != "math" {
			c.report(line, "<%s/>: the slash does not close an HTML element; write </%s>", name, name)
		}
	}

	// Nesting a browser repairs.
	if blockElements[name] && s.within("p") {
		c.report(line, "<%s> inside a <p>, which a browser closes before it", name)
	}
	if name == "form" && s.within("form") {
		c.report(line, "a <form> inside a <form>, which a browser drops")
	}
	if (name == "a" || name == "button") && s.within("a", "button") {
		c.report(line, "<%s> inside a link or a button", name)
	}
	if name == "li" && (parent == nil || (parent.name != "ul" && parent.name != "ol" && parent.name != "menu")) {
		c.report(line, "<li> outside a list")
	}
	if parent != nil {
		if allowed, ok := tableChildren[parent.name]; ok && !allowed[name] && name != "script" && name != "template" {
			c.report(line, "<%s> directly in a <%s>, which a browser moves out of it", name, parent.name)
		}
	}

	// Accessibility.
	named := t.dynamic || t.has("aria-label") || t.has("aria-labelledby")
	switch name {
	case "html":
		if !t.has("lang") && !t.dynamic {
			c.report(line, "<html> has no lang")
		}
	case "img":
		if !t.has("alt") && !t.dynamic {
			c.report(line, "<img> has no alt: describe it, or write alt=\"\" if it only decorates")
		}
		if alt, ok := t.attr("alt"); ok && strings.TrimSpace(alt.value) != "" {
			s.markName()
		}
	case "svg":
		hidden, _ := t.attr("aria-hidden")
		if hidden.value != "true" && !named {
			c.report(line, "<svg> is neither hidden with aria-hidden=\"true\" nor named")
		}
	case "input", "select", "textarea":
		typ, _ := t.attr("type")
		if name == "input" && unlabelledInputTypes[strings.ToLower(typ.value)] {
			break
		}
		if named || s.within("label") {
			break
		}
		id, ok := t.attr("id")
		if !ok {
			c.report(line, "<%s> has no label: give it an id a <label for> names, or aria-label", name)
		} else {
			c.controls = append(c.controls, markupControl{id: id.value, line: line})
		}
	}
	if level, ok := headingLevel[name]; ok {
		if s.heading > 0 && level > s.heading+1 {
			c.report(line, "<%s> follows an <h%d>: heading levels do not skip on the way down", name, s.heading)
		}
		s.heading = level
		if level == 1 {
			c.h1 = append(c.h1, line)
		}
	}

	if voidElements[name] {
		return
	}
	el := openElement{name: name, line: line, named: named}
	if name == "script" {
		typ, hasType := t.attr("type")
		_, hasSrc := t.attr("src")
		switch {
		case hasSrc:
			el.script = "src"
		case hasType && jsonScriptType.MatchString(strings.ToLower(strings.TrimSpace(typ.value))):
			el.script = "json"
		case !hasType || isJavaScriptType(typ.value):
			c.report(line, "an inline <script> runs code: move it to a static file, or make it a "+
				"<script type=\"application/json\"> data block")
			el.script = "code"
		default:
			c.report(line, "<script type=%q> is neither JavaScript nor JSON", typ.value)
			el.script = "other"
		}
	}
	s.stack = append(s.stack, el)
	if rawTextElements[name] {
		s.raw.Reset()
		s.mode = modeRawText
	}
}

func isJavaScriptType(t string) bool {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "", "text/javascript", "application/javascript", "module", "text/ecmascript", "application/ecmascript":
		return true
	}
	return false
}

// closeRawText checks what a raw-text element holds, before its end tag closes it.
func (c *markupChecker) closeRawText(s *markupState) {
	top := s.top()
	body := s.raw.String()
	s.raw.Reset()
	switch top.script {
	case "src":
		if strings.TrimSpace(body) != "" {
			c.report(top.line, "a <script src> also holds code, which a browser never runs")
		}
	case "json":
		if !json.Valid([]byte(body)) {
			c.report(top.line, "the JSON data block is not valid JSON, reading each action as a value")
		}
	}
	if strings.TrimSpace(body) != "" {
		s.stack[len(s.stack)-1].named = true
	}
}

func (c *markupChecker) closeElement(s *markupState, t *markupTag) {
	name := t.name
	if voidElements[name] && !s.foreign() {
		c.report(t.line, "</%s>: a void element has no end tag", name)
		return
	}
	at := -1
	for i := len(s.stack) - 1; i >= 0; i-- {
		if s.stack[i].name == name {
			at = i
			break
		}
	}
	if at < 0 {
		c.report(t.line, "</%s> closes nothing that is open", name)
		return
	}
	for i := len(s.stack) - 1; i > at; i-- {
		c.report(s.stack[i].line, "<%s> is not closed before </%s> on line %d", s.stack[i].name, name, t.line)
	}
	el := s.stack[at]
	named := el.named
	s.stack = s.stack[:at]
	if named {
		s.markName()
	}
	if (name == "a" || name == "button") && !named && !el.foreign {
		c.report(el.line, "<%s> has no name: give it text, or aria-label if it shows only an icon", name)
	}
}

func (c *markupChecker) declareID(s *markupState, a markupAttr, line int) {
	if c.ids == nil {
		c.ids = map[string]bool{}
	}
	c.ids[a.value] = true
	if a.dynamic {
		return
	}
	if s.ranges > 0 {
		c.report(line, "id %q is written inside a {{range}}, so it repeats on the page", a.value)
		return
	}
	if s.branch > 0 {
		return
	}
	c.staticIDs[a.value]++
	if c.staticIDs[a.value] == 2 {
		c.report(line, "id %q is declared twice", a.value)
	}
}

func (c *markupChecker) finishTree(s *markupState) {
	if s.mode != modeText {
		c.report(c.line(0), "the template ends %s", describeShape(s))
	}
	for _, e := range s.stack {
		c.report(e.line, "<%s> is never closed", e.name)
	}
}

func (c *markupChecker) finishFile() {
	for _, ctl := range c.controls {
		if !c.labelFor[ctl.id] {
			c.report(ctl.line, "the control with id %q has no <label for=%q>, and no aria-label", ctl.id, ctl.id)
		}
	}
	for _, ref := range c.refs {
		if !c.ids[ref.id] {
			c.report(ref.line, "%s names id %q, which this template does not declare", ref.attr, ref.id)
		}
	}
	if len(c.h1) > 1 {
		c.report(c.h1[1], "a second <h1>: a page has one, its title")
	}
}

func isMarkupSpace(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\f'
}

func isNameStart(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
}
