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
// Each template file is checked on its own, and each page again as the renderer assembles it: with
// every layout under layouts/ that finds all the templates it calls in the page, and with every
// partial under partials/, a {{template}} call resolved where it is made. A partial is therefore held
// to the place each page puts it, and the rules about a whole page, its one <h1> and the ids its
// references name, are held to the page as it is served. Every fact is kept per branch: an attribute
// or a name present in one branch alone is not taken as present in the other, a label shown in one
// branch labels no control outside it, and two <h1> or two ids in branches that never render together
// do not collide.
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
//     whose body is valid JSON in every branch with each action read as a value, or loads a file with
//     src and has no body; no <script> inside SVG; no on... attribute and no javascript: URL.
//
// Accessibility:
//   - every form control has a label: a <label for> naming its id wherever it renders, a <label>
//     around it, or aria-label or aria-labelledby;
//   - every <img> has alt, every <svg> is hidden from assistive technology or named, and every link
//     and button has a name in every branch: text, an action, or aria-label or aria-labelledby;
//   - a page has one <h1> on every branch, heading levels never skip on the way down, <html> has
//     lang, and no tabindex is positive;
//   - every id that for, aria-labelledby or aria-describedby names is declared wherever the reference
//     renders, and an id written without an action is neither repeated inside {{range}} nor declared
//     twice where both can render.
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

	files := map[string]string{}
	n, err := walkHTMLTemplates(fsys, root, func(path, content string) {
		files[path] = content
	})
	if err != nil {
		r.Fatalf("walking templates under %s: %v", root, err)
	}
	if n == 0 {
		r.Fatalf("walked no .html files under %s; this guard is checking nothing", root)
	}

	set := newTemplateSet(root, files, outOfScope)
	checked := 0
	for _, path := range set.order {
		rel := strings.TrimPrefix(path, root+"/")
		if matchesTemplateList(rel, outOfScope) {
			continue
		}
		found := set.problems(path)
		if listsTemplate(rel, pending) {
			if len(found) == 0 {
				r.Errorf("%s: listed as pending, and already meets every rule; remove it from the list", path)
			}
			continue
		}
		checked++
		for _, f := range found {
			r.Errorf("%s: %s", f.path, f.detail)
		}
	}
	for _, entry := range append(append([]string{}, outOfScope...), pending...) {
		if _, ok := files[root+"/"+entry]; !strings.HasSuffix(entry, "/") && !ok {
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

// findMarkupProblems checks one template file on its own, as a rule test reads it: the file's rules,
// without the rules about a whole page.
func findMarkupProblems(path, content string) []templateFinding {
	set := newTemplateSet("", map[string]string{path: content}, nil)
	f := set.files[path]
	if f.err != nil {
		return []templateFinding{{path: path, detail: "does not parse: " + f.err.Error()}}
	}
	return renderMarkupFindings(set.fileProblems(f))
}

type templateKind int

const (
	pageTemplate templateKind = iota
	layoutTemplate
	partialTemplate
)

// templateFile is one parsed template file: its trees, the file's own and one per {{define}}, and
// where each line of it starts.
type templateFile struct {
	path  string
	lines []int
	trees map[string]*parse.Tree
	err   error
	kind  templateKind
}

type templateSet struct {
	files map[string]*templateFile
	order []string
}

func newTemplateSet(root string, contents map[string]string, outOfScope []string) *templateSet {
	set := &templateSet{files: map[string]*templateFile{}}
	for path, content := range contents {
		rel := strings.TrimPrefix(path, root+"/")
		f := &templateFile{path: path, lines: newlineOffsets(content), trees: map[string]*parse.Tree{}}
		switch {
		case strings.HasPrefix(rel, "layouts/"):
			f.kind = layoutTemplate
		case strings.HasPrefix(rel, "partials/"):
			f.kind = partialTemplate
		}
		if matchesTemplateList(rel, outOfScope) {
			continue
		}
		tree := parse.New(path)
		tree.Mode = parse.SkipFuncCheck | parse.ParseComments
		if _, err := tree.Parse(content, "", "", f.trees); err != nil {
			f.err = err
		}
		set.files[path] = f
		set.order = append(set.order, path)
	}
	sort.Strings(set.order)
	return set
}

// problems returns one finding per rule the file breaks: read on its own, and for a page read as
// served, in each layout that can render it.
func (set *templateSet) problems(path string) []templateFinding {
	f := set.files[path]
	if f.err != nil {
		return []templateFinding{{path: path, detail: "does not parse: " + f.err.Error()}}
	}
	found := set.fileProblems(f)
	if f.kind == pageTemplate {
		found = append(found, set.pageProblems(f)...)
	}
	return renderMarkupFindings(found)
}

// fileProblems reads each of a file's trees on its own, a call to a template the file defines
// resolved where it is made.
func (set *templateSet) fileProblems(f *templateFile) []markupFinding {
	var found []markupFinding
	names := make([]string, 0, len(f.trees))
	for name := range f.trees {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		tree := f.trees[name]
		if tree.Root == nil {
			continue
		}
		w := newMarkupWalk(set, f.trees, false)
		w.walkTree(tree)
		found = append(found, w.found...)
	}
	return found
}

// pageProblems reads a page as served: inside each layout that finds every template it calls in
// the page and the partials, as the renderer parses them, the layout first, then the page, then
// the partials. A page that is a whole document of its own is read alone.
func (set *templateSet) pageProblems(page *templateFile) []markupFinding {
	var found []markupFinding
	rendered := false
	for _, path := range set.order {
		layout := set.files[path]
		if layout.kind != layoutTemplate || layout.err != nil {
			continue
		}
		trees := set.composed(layout, page)
		root := layout.trees[layout.path]
		if root == nil || !resolvesEveryCall(root, trees, map[string]bool{}) {
			continue
		}
		rendered = true
		w := newMarkupWalk(set, trees, true)
		w.pageFile = page.path
		w.page = layout.path
		w.walkTree(root)
		found = append(found, w.found...)
	}
	if rendered {
		return found
	}
	top := page.trees[page.path]
	if top == nil || parse.IsEmptyTree(top.Root) {
		return []markupFinding{{file: page.path, line: 1, message: "no layout under layouts/ finds every template it calls in this page"}}
	}
	trees := set.composed(nil, page)
	w := newMarkupWalk(set, trees, true)
	w.pageFile = page.path
	w.walkTree(top)
	return w.found
}

func (set *templateSet) composed(layout, page *templateFile) map[string]*parse.Tree {
	trees := map[string]*parse.Tree{}
	// A later definition replaces an earlier one, as the renderer parses them, except that an empty
	// one never replaces a template already defined.
	add := func(f *templateFile) {
		for name, tree := range f.trees {
			if tree.Root == nil {
				continue
			}
			if _, defined := trees[name]; defined && parse.IsEmptyTree(tree.Root) {
				continue
			}
			trees[name] = tree
		}
	}
	if layout != nil {
		add(layout)
	}
	add(page)
	for _, path := range set.order {
		if f := set.files[path]; f.kind == partialTemplate && f.err == nil {
			add(f)
		}
	}
	return trees
}

// resolvesEveryCall reports whether every {{template}} call reachable from tree names a template in
// trees.
func resolvesEveryCall(tree *parse.Tree, trees map[string]*parse.Tree, seen map[string]bool) bool {
	ok := true
	var visit func(parse.Node)
	visit = func(node parse.Node) {
		switch n := node.(type) {
		case *parse.ListNode:
			if n != nil {
				for _, c := range n.Nodes {
					visit(c)
				}
			}
		case *parse.IfNode:
			visit(n.List)
			visit(n.ElseList)
		case *parse.WithNode:
			visit(n.List)
			visit(n.ElseList)
		case *parse.RangeNode:
			visit(n.List)
			visit(n.ElseList)
		case *parse.TemplateNode:
			called, found := trees[n.Name]
			if !found {
				ok = false
				return
			}
			if !seen[n.Name] {
				seen[n.Name] = true
				visit(called.Root)
			}
		}
	}
	visit(tree.Root)
	return ok
}

func renderMarkupFindings(found []markupFinding) []templateFinding {
	sort.SliceStable(found, func(i, j int) bool {
		if found[i].file != found[j].file {
			return found[i].file < found[j].file
		}
		return found[i].line < found[j].line
	})
	seen := map[string]bool{}
	out := make([]templateFinding, 0, len(found))
	for _, f := range found {
		detail := fmt.Sprintf("line %d: %s", f.line, f.message)
		if key := f.file + "\x00" + detail; !seen[key] {
			seen[key] = true
			out = append(out, templateFinding{path: f.file, detail: detail + f.context})
		}
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

// markupFinding is one rule broken, at a file and line. context says where a page reading found
// it, the call that reached the template and the layout the page was read in, and is left out when
// findings are matched, so one already found reading the file alone is not reported again.
type markupFinding struct {
	file    string
	line    int
	message string
	context string
}

// markupWhere is where a node is: its file and line, and, inside a template a call reached, where
// the call was made.
type markupWhere struct {
	file string
	line int
	via  string
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

// rawAlternatives bounds the bodies of one raw-text element kept apart, one per combination of
// branches inside it; past it, the first ones are kept.
const rawAlternatives = 32

// markupStep is one branch taken: the branching node, by its tree and position, and which of its
// lists, the body (0) or the else (1).
type markupStep struct {
	tree   string
	pos    int
	branch int
}

// markupPath is the branches taken to reach a fact.
type markupPath []markupStep

// holdsWherever reports whether a fact on path p renders wherever one on q does: p is a prefix of q.
func (p markupPath) holdsWherever(q markupPath) bool {
	if len(p) > len(q) {
		return false
	}
	for i := range p {
		if p[i] != q[i] {
			return false
		}
	}
	return true
}

// covers reports whether facts on the paths given render wherever path p does: one is on a prefix
// of p, or under p every list of one branching node holds a fact, each list covered the same way, as
// an id declared in every arm of an if, else if and else is.
func covers(paths []markupPath, p markupPath) bool {
	for _, f := range paths {
		if f.holdsWherever(p) {
			return true
		}
	}
	nodes := map[markupStep]bool{}
	for _, f := range paths {
		if len(f) > len(p) && p.holdsWherever(f) {
			step := f[len(p)]
			step.branch = 0
			nodes[step] = true
		}
	}
	for node := range nodes {
		all := true
		for branch := 0; branch < 2 && all; branch++ {
			step := node
			step.branch = branch
			all = covers(paths, append(append(markupPath{}, p...), step))
		}
		if all {
			return true
		}
	}
	return false
}

// excludes reports whether facts on p and q never render together: they take different lists of
// one branching node.
func (p markupPath) excludes(q markupPath) bool {
	for i := 0; i < len(p) && i < len(q); i++ {
		if p[i] == q[i] {
			continue
		}
		return p[i].tree == q[i].tree && p[i].pos == q[i].pos && p[i].branch != q[i].branch
	}
	return false
}

type markupAttr struct {
	name  string
	value string // as written, each action spelled as the parser prints it
	maybe bool   // written in some branches only
}

type markupTag struct {
	name      string
	end       bool
	where     markupWhere
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
	n := &markupTag{name: t.name, end: t.end, where: t.where, dynamic: t.dynamic, selfClose: t.selfClose,
		attrName: t.attrName, valueDyn: t.valueDyn}
	n.attrs = append(n.attrs, t.attrs...)
	n.attrValue.WriteString(t.attrValue.String())
	return n
}

// attr returns the attribute name written in every branch.
func (t *markupTag) attr(name string) (markupAttr, bool) {
	for _, a := range t.attrs {
		if a.name == name && !a.maybe {
			return a, true
		}
	}
	return markupAttr{}, false
}

func (t *markupTag) has(name string) bool {
	_, ok := t.attr(name)
	return ok
}

func (t *markupTag) written(name string) bool {
	for _, a := range t.attrs {
		if a.name == name {
			return true
		}
	}
	return false
}

type openElement struct {
	name    string
	where   markupWhere
	foreign bool
	named   bool // it holds text, an action or a named image, or carries a name of its own
	script  string
}

type markupState struct {
	mode    markupMode
	quote   byte
	tag     *markupTag
	stack   []openElement
	raw     []string
	path    markupPath
	ranges  int
	heading int
}

func (s *markupState) clone() *markupState {
	n := &markupState{mode: s.mode, quote: s.quote, tag: s.tag.clone(), ranges: s.ranges, heading: s.heading}
	n.stack = append(n.stack, s.stack...)
	n.raw = append(n.raw, s.raw...)
	n.path = append(n.path, s.path...)
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
			if s.stack[i].name == n && !s.stack[i].foreign {
				return true
			}
		}
	}
	return false
}

// svgHTMLPoints are the SVG elements whose content is HTML again.
var svgHTMLPoints = map[string]bool{"foreignObject": true, "desc": true, "title": true}

// foreign reports whether the next element is SVG or MathML content rather than HTML.
func (s *markupState) foreign() bool {
	top := s.top()
	if top == nil {
		return false
	}
	if top.foreign {
		return !svgHTMLPoints[top.name]
	}
	return top.name == "svg" || top.name == "math"
}

// markName marks every open element as holding content a name can come from.
func (s *markupState) markName() {
	for i := range s.stack {
		s.stack[i].named = true
	}
}

func (s *markupState) appendRaw(text string) {
	if len(s.raw) == 0 {
		s.raw = []string{""}
	}
	for i := range s.raw {
		s.raw[i] += text
	}
}

type markupFact struct {
	value string
	path  markupPath
	where markupWhere
}

type markupID struct {
	markupFact
	dynamic bool
}

type markupRef struct {
	markupFact
	attr string
}

// markupWalk is one reading of a template tree, every call it makes resolved against trees: a file
// alone, or a page as served. Facts about ids, labels and headings are kept for the whole reading.
type markupWalk struct {
	set      *templateSet
	trees    map[string]*parse.Tree
	whole    bool   // the reading is a whole page, which owes one <h1>
	pageFile string // the page, when the reading is one
	page     string // the layout the page is read in, when it is
	frames   []markupFrame
	found    []markupFinding
	ids      []markupID
	labels   []markupFact
	controls []markupFact
	refs     []markupRef
	h1       []markupFact
}

type markupFrame struct {
	tree *parse.Tree
	file *templateFile
	via  string
}

func newMarkupWalk(set *templateSet, trees map[string]*parse.Tree, whole bool) *markupWalk {
	return &markupWalk{set: set, trees: trees, whole: whole}
}

func (w *markupWalk) at(pos int) markupWhere {
	frame := w.frames[len(w.frames)-1]
	return markupWhere{file: frame.file.path, line: sort.SearchInts(frame.file.lines, pos) + 1, via: frame.via}
}

func (w *markupWalk) reportAt(where markupWhere, format string, args ...any) {
	context := ""
	if where.via != "" {
		context += " (where " + where.via + " calls it)"
	}
	context += pageSuffix(w.page)
	w.found = append(w.found, markupFinding{file: where.file, line: where.line, message: fmt.Sprintf(format, args...), context: context})
}

func (w *markupWalk) report(pos int, format string, args ...any) {
	w.reportAt(w.at(pos), format, args...)
}

func (w *markupWalk) walkTree(tree *parse.Tree) {
	w.frames = append(w.frames, markupFrame{tree: tree, file: w.set.files[tree.ParseName]})
	s := &markupState{}
	w.walkList(s, tree.Root)
	w.finish(s)
	w.frames = w.frames[:len(w.frames)-1]
}

func (w *markupWalk) walkList(s *markupState, list *parse.ListNode) {
	if list == nil {
		return
	}
	for _, node := range list.Nodes {
		w.walkNode(s, node)
	}
}

func (w *markupWalk) walkNode(s *markupState, node parse.Node) {
	switch n := node.(type) {
	case *parse.TextNode:
		w.text(s, string(n.Text), int(n.Pos))
	case *parse.ActionNode:
		if n.Pipe != nil && (len(n.Pipe.Decl) > 0 || n.Pipe.IsAssign) {
			return // a declaration or an assignment renders nothing
		}
		w.action(s, n.String(), int(n.Pos))
	case *parse.TemplateNode:
		w.call(s, n)
	case *parse.IfNode:
		w.branches(s, int(n.Pos), false, n.List, n.ElseList)
	case *parse.WithNode:
		w.branches(s, int(n.Pos), false, n.List, n.ElseList)
	case *parse.RangeNode:
		w.branches(s, int(n.Pos), true, n.List, n.ElseList)
	case *parse.ListNode:
		w.walkList(s, n)
	}
}

// call reads the template a {{template}} names where the call is made, when it is one of the
// trees the reading resolves against; otherwise the call stands for whatever it renders.
func (w *markupWalk) call(s *markupState, n *parse.TemplateNode) {
	called, ok := w.trees[n.Name]
	if !ok || len(w.frames) > 16 {
		w.action(s, n.String(), int(n.Pos))
		return
	}
	for _, f := range w.frames {
		if f.tree == called {
			w.action(s, n.String(), int(n.Pos))
			return
		}
	}
	site := w.at(int(n.Pos))
	via := fmt.Sprintf("%s line %d", site.file, site.line)
	w.frames = append(w.frames, markupFrame{tree: called, file: w.set.files[called.ParseName], via: via})
	w.walkList(s, called.Root)
	w.frames = w.frames[:len(w.frames)-1]
}

// branches walks each list of a branching node from the state before it, and requires each to end
// in that state: what a branch opens, it closes. The state after is the state before, holding what
// every branch added to it: an attribute written in all, a name every branch gives an element still
// open, and, inside a raw-text element, each branch's body as an alternative of its own.
func (w *markupWalk) branches(s *markupState, pos int, isRange bool, body, otherwise *parse.ListNode) {
	w.settle(s)
	before := s.clone()
	tree := w.frames[len(w.frames)-1].tree.ParseName
	var ends []*markupState
	for i, list := range []*parse.ListNode{body, otherwise} {
		b := before.clone()
		b.path = append(b.path, markupStep{tree: tree, pos: pos, branch: i})
		if isRange && i == 0 {
			b.ranges++
		}
		w.walkList(b, list)
		w.settle(b)
		ends = append(ends, b)
	}
	shaped := true
	for _, b := range ends {
		if !sameShape(before, b) {
			shaped = false
			w.report(pos, "a branch ends %s, where it began %s: what a branch opens it closes, "+
				"so the page reads the same whichever branch runs", describeShape(b), describeShape(before))
		}
	}
	if !shaped {
		return
	}

	for i := range s.stack {
		all := true
		for _, b := range ends {
			all = all && b.stack[i].named
		}
		s.stack[i].named = s.stack[i].named || all
	}
	if s.tag != nil {
		for _, b := range ends {
			s.tag.dynamic = s.tag.dynamic || b.tag.dynamic
			for _, a := range b.tag.attrs {
				if s.tag.written(a.name) {
					continue
				}
				inAll := true
				for _, other := range ends {
					inAll = inAll && other.tag.has(a.name)
				}
				a.maybe = !inAll
				s.tag.attrs = append(s.tag.attrs, a)
			}
		}
	}
	if s.mode == modeRawText {
		s.raw = nil
		for _, b := range ends {
			s.raw = append(s.raw, b.raw...)
		}
		if len(s.raw) > rawAlternatives {
			s.raw = s.raw[:rawAlternatives]
		}
	}
	for _, b := range ends {
		if b.heading > s.heading {
			s.heading = b.heading
		}
	}
}

// settle completes a tag name or an attribute name in progress: one written alone in a branch, such
// as {{if .checked}}checked{{end}}, ends where the branch does.
func (w *markupWalk) settle(s *markupState) {
	if s.mode == modeTagName {
		s.mode = modeTag
	}
	if s.mode == modeAttrName || s.mode == modeAfterAttrName {
		w.commitAttr(s)
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

func (w *markupWalk) action(s *markupState, spelled string, pos int) {
	switch s.mode {
	case modeText:
		s.markName()
	case modeTagOpen:
		w.report(pos, "an action writes a tag's name; write the name")
		s.tag = &markupTag{name: "?", where: w.at(pos)}
		s.mode = modeTagName
	case modeTagName, modeTag, modeAfterAttrName, modeSelfClosing:
		if s.mode == modeAfterAttrName {
			w.commitAttr(s)
		}
		s.tag.dynamic = true
		s.mode = modeTag
	case modeAttrName:
		s.tag.attrName += spelled
	case modeBeforeValue, modeValueUnquoted:
		w.report(pos, "attribute %s is not quoted: write %s=\"%s\"", s.tag.attrName, s.tag.attrName, spelled)
		s.tag.attrValue.WriteString(spelled)
		s.tag.valueDyn = true
		s.mode = modeValueUnquoted
	case modeValue:
		s.tag.attrValue.WriteString(spelled)
		s.tag.valueDyn = true
	case modeRawText:
		s.appendRaw(hole)
	case modeComment, modeDeclaration:
	}
}

// rawTextEnd returns where the end tag of the raw-text element name starts in lower, the rest of a
// text node lowercased: "</name" followed by a space, a slash, a ">" or the end of the node, which
// is where a browser ends the element. -1 when the node holds none.
func rawTextEnd(lower, name string) int {
	from := 0
	for {
		at := strings.Index(lower[from:], "</"+name)
		if at < 0 {
			return -1
		}
		at += from
		after := at + 2 + len(name)
		if after == len(lower) || isMarkupSpace(lower[after]) || lower[after] == '/' || lower[after] == '>' {
			return at
		}
		from = at + 1
	}
}

func (w *markupWalk) text(s *markupState, text string, base int) {
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
					w.report(pos, "text directly in a <%s>, which a browser moves out of it", top.name)
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
				s.tag = &markupTag{end: true, where: w.at(pos)}
				s.mode = modeTagName
			case isNameStart(ch):
				s.tag = &markupTag{name: string(ch), where: w.at(pos)}
				s.mode = modeTagName
			default:
				w.report(pos, "a bare < in text: write &lt;")
				s.mode = modeText
				i--
			}
		case modeTagName:
			switch {
			case isMarkupSpace(ch):
				s.mode = modeTag
			case ch == '>':
				w.finishTag(s)
			case ch == '/':
				s.mode = modeSelfClosing
			default:
				s.tag.name += string(ch)
			}
		case modeTag:
			switch {
			case isMarkupSpace(ch):
			case ch == '>':
				w.finishTag(s)
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
				w.commitAttr(s)
				w.finishTag(s)
			case ch == '/':
				w.commitAttr(s)
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
				w.commitAttr(s)
				w.finishTag(s)
			case ch == '/':
				w.commitAttr(s)
				s.mode = modeSelfClosing
			default:
				w.commitAttr(s)
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
				w.report(pos, "attribute %s has an = and no value", s.tag.attrName)
				w.commitAttr(s)
				w.finishTag(s)
			default:
				w.report(pos, "attribute %s is not quoted", s.tag.attrName)
				s.tag.attrValue.WriteByte(ch)
				s.mode = modeValueUnquoted
			}
		case modeValue:
			if ch == s.quote {
				w.commitAttr(s)
				s.quote = 0
				s.mode = modeTag
			} else {
				s.tag.attrValue.WriteByte(ch)
			}
		case modeValueUnquoted:
			switch {
			case isMarkupSpace(ch):
				w.commitAttr(s)
				s.mode = modeTag
			case ch == '>':
				w.commitAttr(s)
				w.finishTag(s)
			default:
				s.tag.attrValue.WriteByte(ch)
			}
		case modeSelfClosing:
			if ch == '>' {
				s.tag.selfClose = true
				w.finishTag(s)
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
			at := rawTextEnd(strings.ToLower(text[i:]), s.top().name)
			if at < 0 {
				s.appendRaw(text[i:])
				return
			}
			s.appendRaw(text[i : i+at])
			w.closeRawText(s)
			s.tag = &markupTag{end: true, where: w.at(base + i + at)}
			s.mode = modeTagName
			i += at + 1
		}
	}
}

// commitAttr completes the attribute in progress, and records the ids it declares and the ids it
// names on the branches it is written in.
func (w *markupWalk) commitAttr(s *markupState) {
	t := s.tag
	name := strings.ToLower(t.attrName)
	value := t.attrValue.String()
	dynamic := t.valueDyn
	t.attrName = ""
	t.attrValue.Reset()
	t.valueDyn = false
	if name == "" {
		return
	}
	if t.written(name) {
		w.reportAt(t.where, "<%s> carries %s twice", t.name, name)
		return
	}
	t.attrs = append(t.attrs, markupAttr{name: name, value: value})

	fact := markupFact{value: value, path: append(markupPath{}, s.path...), where: t.where}
	switch name {
	case "id":
		if !dynamic && s.ranges > 0 {
			w.reportAt(t.where, "id %q is written inside a {{range}}, so it repeats on the page", value)
		}
		w.ids = append(w.ids, markupID{markupFact: fact, dynamic: dynamic})
	case "aria-labelledby", "aria-describedby":
		for _, id := range strings.Fields(value) {
			ref := fact
			ref.value = id
			w.refs = append(w.refs, markupRef{markupFact: ref, attr: name})
		}
	case "for":
		if strings.EqualFold(t.name, "label") {
			w.labels = append(w.labels, fact)
			w.refs = append(w.refs, markupRef{markupFact: fact, attr: "for"})
		}
	}
}

func (w *markupWalk) finishTag(s *markupState) {
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
		w.closeElement(s, t)
		return
	}
	w.startElement(s, t, foreign)
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

func (w *markupWalk) startElement(s *markupState, t *markupTag, foreign bool) {
	name, where := t.name, t.where
	parent := s.top()

	for _, a := range t.attrs {
		if strings.HasPrefix(a.name, "on") && len(a.name) > 2 {
			w.reportAt(where, "<%s> carries %s: register the handler from a static script", name, a.name)
		}
		switch a.name {
		case "href", "src", "action", "formaction", "xlink:href":
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(a.value)), "javascript:") {
				w.reportAt(where, "<%s %s> is a javascript: URL: register the behaviour from a static script", name, a.name)
			}
		case "tabindex":
			if n, err := strconv.Atoi(strings.TrimSpace(a.value)); err == nil && n > 0 {
				w.reportAt(where, "<%s> has tabindex %d: a positive tabindex reorders the keyboard path", name, n)
			}
		}
	}

	if foreign {
		if strings.EqualFold(name, "script") {
			w.reportAt(where, "a <script> inside SVG runs code: move it to a static file")
		}
		if t.selfClose {
			return
		}
		s.stack = append(s.stack, openElement{name: name, where: where, foreign: true})
		return
	}

	if t.selfClose {
		if voidElements[name] {
			w.reportAt(where, "<%s/>: write a void element without the trailing slash", name)
		} else if name != "svg" && name != "math" {
			w.reportAt(where, "<%s/>: the slash does not close an HTML element; write </%s>", name, name)
		}
	}

	// Nesting a browser repairs.
	if blockElements[name] && s.within("p") {
		w.reportAt(where, "<%s> inside a <p>, which a browser closes before it", name)
	}
	if name == "form" && s.within("form") {
		w.reportAt(where, "a <form> inside a <form>, which a browser drops")
	}
	if (name == "a" || name == "button") && s.within("a", "button") {
		w.reportAt(where, "<%s> inside a link or a button", name)
	}
	if name == "li" && (parent == nil || parent.foreign || (parent.name != "ul" && parent.name != "ol" && parent.name != "menu")) {
		w.reportAt(where, "<li> outside a list")
	}
	if parent != nil && !parent.foreign {
		if allowed, ok := tableChildren[parent.name]; ok && !allowed[name] && name != "script" && name != "template" {
			w.reportAt(where, "<%s> directly in a <%s>, which a browser moves out of it", name, parent.name)
		}
	}

	// Accessibility.
	named := t.dynamic || t.has("aria-label") || t.has("aria-labelledby")
	switch name {
	case "html":
		if !t.has("lang") && !t.dynamic {
			w.reportAt(where, "<html> has no lang")
		}
	case "img":
		if !t.has("alt") && !t.dynamic {
			w.reportAt(where, "<img> has no alt: describe it, or write alt=\"\" if it only decorates")
		}
		if alt, ok := t.attr("alt"); ok && strings.TrimSpace(alt.value) != "" {
			s.markName()
		}
	case "svg":
		hidden, _ := t.attr("aria-hidden")
		if hidden.value != "true" && !named {
			w.reportAt(where, "<svg> is neither hidden with aria-hidden=\"true\" nor named")
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
			w.reportAt(where, "<%s> has no label: give it an id a <label for> names, or aria-label", name)
		} else {
			w.controls = append(w.controls, markupFact{value: id.value, path: append(markupPath{}, s.path...), where: where})
		}
	}
	if level, ok := headingLevel[name]; ok {
		if s.heading > 0 && level > s.heading+1 {
			w.reportAt(where, "<%s> follows an <h%d>: heading levels do not skip on the way down", name, s.heading)
		}
		s.heading = level
		if level == 1 {
			w.h1 = append(w.h1, markupFact{path: append(markupPath{}, s.path...), where: where})
		}
	}

	if voidElements[name] {
		return
	}
	el := openElement{name: name, where: where, named: named}
	if name == "script" {
		typ, hasType := t.attr("type")
		switch {
		case t.written("src"):
			el.script = "src"
		case hasType && jsonScriptType.MatchString(strings.ToLower(strings.TrimSpace(typ.value))):
			el.script = "json"
		case !t.written("type") || isJavaScriptType(typ.value):
			w.reportAt(where, "an inline <script> runs code: move it to a static file, or make it a "+
				"<script type=\"application/json\"> data block")
			el.script = "code"
		default:
			w.reportAt(where, "<script type=%q> is neither JavaScript nor JSON", typ.value)
			el.script = "other"
		}
	}
	s.stack = append(s.stack, el)
	if rawTextElements[name] {
		s.raw = []string{""}
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

// closeRawText checks what a raw-text element holds, in each of its alternatives, before its end
// tag closes it.
func (w *markupWalk) closeRawText(s *markupState) {
	top := s.top()
	bodies := s.raw
	s.raw = nil
	nonEmpty := false
	for _, body := range bodies {
		if strings.TrimSpace(body) != "" {
			nonEmpty = true
		}
	}
	switch top.script {
	case "src":
		if nonEmpty {
			w.reportAt(top.where, "a <script src> also holds code, which a browser never runs")
		}
	case "json":
		for _, body := range bodies {
			if !json.Valid([]byte(body)) {
				w.reportAt(top.where, "the JSON data block is not valid JSON in every branch, reading each action as a value")
				break
			}
		}
	}
	if nonEmpty {
		top.named = true
	}
}

func (w *markupWalk) closeElement(s *markupState, t *markupTag) {
	name := t.name
	if voidElements[name] && !s.foreign() {
		w.reportAt(t.where, "</%s>: a void element has no end tag", name)
		return
	}
	at := -1
	for i := len(s.stack) - 1; i >= 0; i-- {
		if strings.EqualFold(s.stack[i].name, name) {
			at = i
			break
		}
	}
	if at < 0 {
		w.reportAt(t.where, "</%s> closes nothing that is open", name)
		return
	}
	for i := len(s.stack) - 1; i > at; i-- {
		w.reportAt(s.stack[i].where, "<%s> is not closed before </%s> on line %d", s.stack[i].name, name, t.where.line)
	}
	el := s.stack[at]
	s.stack = s.stack[:at]
	if el.named {
		s.markName()
	}
	if (name == "a" || name == "button") && !el.named && !el.foreign {
		w.reportAt(el.where, "<%s> has no name in every branch: give it text, or aria-label if it shows only an icon", name)
	}
}

// finish checks what a reading leaves: the state it ends in, and the facts about the whole tree.
func (w *markupWalk) finish(s *markupState) {
	if s.mode != modeText {
		w.report(0, "the template ends %s", describeShape(s))
	}
	for _, e := range s.stack {
		w.reportAt(e.where, "<%s> is never closed", e.name)
	}

	pathsOf := func(facts []markupFact, value string) []markupPath {
		var paths []markupPath
		for _, f := range facts {
			if f.value == value {
				paths = append(paths, f.path)
			}
		}
		return paths
	}
	declared := make([]markupFact, 0, len(w.ids))
	for _, id := range w.ids {
		declared = append(declared, id.markupFact)
	}
	for _, ctl := range w.controls {
		if !covers(pathsOf(w.labels, ctl.value), ctl.path) {
			w.reportAt(ctl.where, "the control with id %q has no <label for=%q> wherever it renders, and no aria-label", ctl.value, ctl.value)
		}
	}
	for _, ref := range w.refs {
		if !covers(pathsOf(declared, ref.value), ref.path) {
			w.reportAt(ref.where, "%s names id %q, which is not declared wherever the reference renders", ref.attr, ref.value)
		}
	}
	for i, a := range w.ids {
		for _, b := range w.ids[:i] {
			if !a.dynamic && !b.dynamic && a.value == b.value && !a.path.excludes(b.path) {
				w.reportAt(a.where, "id %q is declared twice where both can render", a.value)
				break
			}
		}
	}
	for i, a := range w.h1 {
		for _, b := range w.h1[:i] {
			if !a.path.excludes(b.path) {
				w.reportAt(a.where, "a second <h1>: a page has one, its title")
				break
			}
		}
	}
	if w.whole {
		unconditional := false
		for _, h := range w.h1 {
			unconditional = unconditional || len(h.path) == 0
		}
		if !unconditional {
			w.found = append(w.found, markupFinding{file: w.pageFile, line: 1,
				message: "the page has no <h1> on every branch", context: pageSuffix(w.page)})
		}
	}
}

func pageSuffix(page string) string {
	if page == "" {
		return ""
	}
	return " (in " + page + ")"
}

func isMarkupSpace(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\f'
}

func isNameStart(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
}
