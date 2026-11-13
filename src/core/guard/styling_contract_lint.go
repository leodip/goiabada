package guard

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"testing"
	"text/template/parse"
)

// pageNameTemplate is the template a page in the styling contract defines to name itself, as
// core/stylingcontract.PageTemplate names it. The guard reads it by its spelling rather than
// importing the contract, which the callers hand it.
const pageNameTemplate = "data-page"

// StylingContract is what one server's pages promise a brand's custom CSS (#816), as
// core/stylingcontract lists it for that server.
type StylingContract struct {
	// Pages are the data-page values this server's pages carry, one page each.
	Pages []string
	// Classes are the hook classes promised on this server's pages.
	Classes []string
	// Variables are the CSS variables promised, which the server's main.css declares.
	Variables []string
	// Outside names the page templates outside the contract, as paths under the root: a path, a
	// pattern path.Match reads, such as admin_*.html, or a directory ending in "/".
	Outside []string
}

// AssertStylingContract holds one server's templates to the styling contract (#816 decision 7),
// so a page, a hook class or a variable an administrator's custom CSS relies on cannot leave a
// release unnoticed.
//
// Every page template under root that Outside does not name is in the contract. Each one defines a
// "data-page" template holding its value and nothing else, a value contract.Pages lists and no
// other page names; read as served, in each layout a handler under handlers renders it in with the
// partials, or alone when it is a whole document, its <body> writes a data-page attribute. Every
// listed value has a page. Every hook class in contract.Classes is drawn by some page in the
// contract as served, in any branch: a class only a page outside the contract draws, or only a
// partial no page calls, is drawn by none. Every variable in contract.Variables is declared in css,
// the server's main.css. Pages are read through the parse trees AssertWellFormedTemplates reads.
//
// An Outside entry naming no page is reported, so the list holds only what it exempts. No page
// under root, every page outside the contract, handlers rendering no page and a stylesheet
// declaring no variable are fatal, because nothing would be checked.
func AssertStylingContract(t *testing.T, fsys fs.FS, root, handlers string, css []byte, contract StylingContract) {
	t.Helper()

	assertStylingContract(t, fsys, root, os.DirFS(handlers), css, contract)
}

// assertStylingContract is the reporting half, failing through a Reporter so a rule test can drive
// it against fixture trees. See Reporter in guard.go.
func assertStylingContract(r Reporter, fsys fs.FS, root string, handlers fs.FS, css []byte, contract StylingContract) {
	r.Helper()

	bindings, _, err := findRenderBindings(handlers)
	if err != nil {
		r.Fatalf("reading the handlers for the pages they render: %v", err)
	}
	if len(bindings) == 0 {
		r.Fatalf("found no RenderTemplate call naming a layout and a page; this guard is checking nothing")
	}
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
	declared := declaredVariables(string(css))
	if len(declared) == 0 {
		r.Fatalf("the stylesheet declares no variable; this guard is checking nothing")
	}

	found, checked := findStylingContractProblems(newTemplateSet(root, files, nil, bindings), contract)
	if checked == 0 {
		r.Fatalf("every page under %s is outside the contract; this guard is checking nothing", root)
	}
	for _, f := range found {
		r.Errorf("%s", f)
	}
	for _, v := range contract.Variables {
		if !declared[v] {
			r.Errorf("%s: promised, and main.css declares no such variable; declare it again, or take it out of the contract in the release notes", v)
		}
	}
}

// findStylingContractProblems is the finder: one finding per broken promise of the pages in set,
// and how many pages in the contract it read.
func findStylingContractProblems(set *templateSet, contract StylingContract) ([]string, int) {
	var found []string
	reached := map[string]bool{}
	namedBy := map[string]string{}
	drawn := map[string]bool{}
	checked := 0
	for _, p := range set.order {
		f := set.files[p]
		if f.kind != pageTemplate {
			continue
		}
		if entry, ok := outsideContract(set.rel(p), contract.Outside); ok {
			reached[entry] = true
			continue
		}
		checked++
		if f.err != nil {
			found = append(found, fmt.Sprintf("%s: does not parse: %v", p, f.err))
			continue
		}
		if problem := pageNameProblem(f, contract.Pages, namedBy); problem != "" {
			found = append(found, problem)
		}
		found = append(found, servedPageProblems(set, f, drawn)...)
	}
	for _, page := range contract.Pages {
		if _, ok := namedBy[page]; !ok {
			found = append(found, fmt.Sprintf("data-page %q: listed, and no page names it; name a page with it, or take it out of the contract in the release notes", page))
		}
	}
	for _, class := range contract.Classes {
		if !drawn[class] {
			found = append(found, fmt.Sprintf("hook class %q: promised, and no page in the contract draws it; draw it again, or take it out of the contract in the release notes", class))
		}
	}
	for _, entry := range contract.Outside {
		if !reached[entry] {
			found = append(found, fmt.Sprintf("%s: listed as outside the contract, and no page there was reached; remove it from the list", entry))
		}
	}
	return found, checked
}

// outsideContract answers the Outside entry naming rel, a page's path under the root, if one does.
func outsideContract(rel string, outside []string) (string, bool) {
	for _, entry := range outside {
		if strings.HasSuffix(entry, "/") {
			if strings.HasPrefix(rel, entry) {
				return entry, true
			}
			continue
		}
		if ok, err := path.Match(entry, rel); err == nil && ok {
			return entry, true
		}
	}
	return "", false
}

// pageNameProblem reads the value page names in its data-page template, recording it in namedBy,
// and answers what is wrong with it, or "".
func pageNameProblem(page *templateFile, listed []string, namedBy map[string]string) string {
	tree := page.trees[pageNameTemplate]
	if tree == nil || tree.Root == nil || parse.IsEmptyTree(tree.Root) {
		return fmt.Sprintf("%s: defines no %q template; give it the page's data-page value", page.path, pageNameTemplate)
	}
	line := sort.SearchInts(page.lines, int(tree.Root.Pos)) + 1
	var name strings.Builder
	for _, node := range tree.Root.Nodes {
		text, ok := node.(*parse.TextNode)
		if !ok {
			return fmt.Sprintf("%s: line %d: its %q template writes more than the page's name; write the value alone", page.path, line, pageNameTemplate)
		}
		name.Write(text.Text)
	}
	value := strings.TrimSpace(name.String())
	if !slices.Contains(listed, value) {
		return fmt.Sprintf("%s: line %d: names data-page %q, which the contract does not list for this server", page.path, line, value)
	}
	if other, ok := namedBy[value]; ok {
		return fmt.Sprintf("%s: line %d: names data-page %q, which %s names too; give each page a value of its own", page.path, line, value, other)
	}
	namedBy[value] = page.path
	return ""
}

// servedPageProblems reads page as served, recording in drawn every class it draws, and reports
// each reading whose <body> writes no data-page. A page no handler renders that is no whole
// document of its own is not read: AssertWellFormedTemplates reports it.
func servedPageProblems(set *templateSet, page *templateFile, drawn map[string]bool) []string {
	type reading struct {
		layout string
		trees  map[string]*parse.Tree
		root   *parse.Tree
	}
	var readings []reading
	if layouts := set.bindings[set.rel(page.path)]; len(layouts) > 0 {
		for _, name := range layouts {
			p := name
			if set.root != "" {
				p = set.root + "/" + name
			}
			if layout := set.files[p]; layout != nil && layout.err == nil {
				readings = append(readings, reading{layout.path, set.composed(layout, page), layout.trees[layout.path]})
			}
		}
	} else if top := page.trees[page.path]; top != nil && !parse.IsEmptyTree(top.Root) {
		readings = append(readings, reading{"", set.composed(nil, page), top})
	}
	var found []string
	for _, rd := range readings {
		body, named := false, false
		w := newMarkupWalk(set, rd.trees, pageReading)
		w.pageFile = page.path
		w.onElement = func(t *markupTag) {
			if t.name == "body" {
				body = true
				named = named || t.written("data-page")
			}
			for _, a := range t.attrs {
				if a.name != "class" {
					continue
				}
				for _, v := range a.alts {
					for _, c := range classesIn(v.text) {
						if !c.prefix {
							drawn[c.name] = true
						}
					}
				}
			}
		}
		w.walkTree(rd.root)
		if !named {
			where := ""
			if rd.layout != "" {
				where = " as served in " + rd.layout + ","
			}
			if body {
				found = append(found, fmt.Sprintf("%s:%s <body> carries no data-page; write data-page=\"{{ . }}\" from .dataPage", page.path, where))
			} else {
				found = append(found, fmt.Sprintf("%s:%s draws no <body> to carry its data-page", page.path, where))
			}
		}
	}
	return found
}

// declaredVariables reads the custom properties a stylesheet declares: a name beginning "--"
// followed by a colon, outside comments and strings, where a declaration can start, so a var()
// reading one declares nothing.
func declaredVariables(css string) map[string]bool {
	declared := map[string]bool{}
	start := true
	for i := 0; i < len(css); i++ {
		switch c := css[i]; {
		case strings.HasPrefix(css[i:], "/*"):
			end := strings.Index(css[i+2:], "*/")
			if end < 0 {
				return declared
			}
			i += end + 3
		case c == '"' || c == '\'':
			j := i + 1
			for j < len(css) && css[j] != c {
				if css[j] == '\\' {
					j++
				}
				j++
			}
			i = j
			start = false
		case c == '{' || c == ';' || c == '}':
			start = true
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f':
		case start && strings.HasPrefix(css[i:], "--"):
			name, next := cssIdent(css, i)
			rest := strings.TrimLeft(css[next:], " \t\n\r\f")
			if strings.HasPrefix(rest, ":") {
				declared[name] = true
			}
			i = next - 1
			start = false
		default:
			start = false
		}
	}
	return declared
}
