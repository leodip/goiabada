package guard

import (
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/leodip/goiabada/core/errs"
)

// AssertClassesAreDrawn holds every class a page names to a rule in css, the application's
// generated main.css (#617). A class with no rule is a misspelling or a leftover of a stylesheet
// that is gone, and the element is drawn as though it were not there, which nothing else notices.
//
// Pages are read as AssertWellFormedTemplates reads them, through each template's parse tree: a
// class attribute's value once per combination of the branches inside it, comments left out, so
// class="button{{if .Danger}}-danger{{end}}" names button and button-danger. A class an action
// completes, theme-swatch-{{ . }}, is a prefix, held to some class beginning with it; one an action
// writes whole is not read. The stylesheet's classes are read from its selectors, CSS escapes
// decoded. Classes a script sets are not read: the scripts set a few, by hand.
//
// outOfScope names the files no rule reads, as the walked FS spells them, a path or a directory
// ending in "/": the email templates, which main.css does not style. No tree, a tree that reaches no
// .html file, and a stylesheet that defines no class are fatal, because nothing would be checked.
func AssertClassesAreDrawn(t *testing.T, css []byte, outOfScope []string, trees ...fs.FS) {
	t.Helper()

	assertClassesAreDrawn(t, css, outOfScope, trees...)
}

// assertClassesAreDrawn is the reporting half, failing through a Reporter so a rule test can drive
// it against fixture trees. See Reporter in guard.go.
func assertClassesAreDrawn(r Reporter, css []byte, outOfScope []string, trees ...fs.FS) {
	r.Helper()

	if len(trees) == 0 {
		r.Fatalf("given no tree of pages; this guard is checking nothing")
	}
	drawn := drawnClasses(string(css))
	if len(drawn) == 0 {
		r.Fatalf("the stylesheet defines no class; this guard is checking nothing")
	}
	listed := map[string]bool{}
	for _, tree := range trees {
		named, n, err := findNamedClasses(tree, outOfScope, listed)
		if err != nil {
			r.Fatalf("walking for pages: %v", err)
		}
		if n == 0 {
			r.Fatalf("reached no .html file in one of the trees; this guard is checking nothing")
		}
		for _, c := range named {
			switch {
			case c.prefix && !drawsPrefix(drawn, c.name):
				r.Errorf("%s: line %d: no class in main.css begins with %q; correct the class, or regenerate main.css", c.path, c.line, c.name)
			case !c.prefix && !drawn[c.name]:
				r.Errorf("%s: line %d: class %q has no rule in main.css; correct the class, or regenerate main.css", c.path, c.line, c.name)
			}
		}
	}
	for _, entry := range outOfScope {
		if !listed[entry] {
			r.Errorf("%s: listed as out of scope, and no file there was reached; remove it from the list", entry)
		}
	}
}

// namedClass is a class a page names, or, with prefix, the start of one it completes
// with a value.
type namedClass struct {
	path   string
	line   int
	name   string
	prefix bool
}

func drawsPrefix(drawn map[string]bool, prefix string) bool {
	for name := range drawn {
		if len(name) > len(prefix) && strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func findNamedClasses(fsys fs.FS, outOfScope []string, listed map[string]bool) ([]namedClass, int, error) {
	var named []namedClass
	n := 0
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".html") {
			return nil
		}
		for _, entry := range outOfScope {
			if matchesTemplateList(p, []string{entry}) {
				listed[entry] = true
				return nil
			}
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		n++
		found, err := pageClasses(p, string(b))
		if err != nil {
			return err
		}
		named = append(named, found...)
		return nil
	})
	return named, n, err
}

// pageClasses reads the classes of every class attribute in a page, each tree of the file walked as
// the markup guard walks it, a class read once wherever two trees reach the same attribute.
func pageClasses(path, src string) ([]namedClass, error) {
	set := newTemplateSet("", map[string]string{path: src}, nil, nil)
	f := set.files[path]
	if f.err != nil {
		return nil, errs.Wrapf(f.err, "%s does not parse", path)
	}
	names := make([]string, 0, len(f.trees))
	for name := range f.trees {
		names = append(names, name)
	}
	sort.Strings(names)
	seen := map[namedClass]bool{}
	var named []namedClass
	for _, name := range names {
		if f.trees[name].Root == nil {
			continue
		}
		w := newMarkupWalk(set, f.trees, fileReading)
		w.onElement = func(t *markupTag) {
			for _, a := range t.attrs {
				if a.name != "class" {
					continue
				}
				for _, v := range a.alts {
					for _, c := range classesIn(v.text) {
						c.path, c.line = path, t.where.line
						if !seen[c] {
							seen[c] = true
							named = append(named, c)
						}
					}
				}
			}
		}
		w.walkTree(f.trees[name])
	}
	return named, nil
}

// printedAction is an action left in an attribute's text, which prints a value.
var printedAction = regexp.MustCompile(`\{\{.*?\}\}`)

// printed stands for the text an action prints, inside a class it completes.
const printed = "\x00"

// classesIn reads the classes one text of a class attribute names.
func classesIn(text string) []namedClass {
	var named []namedClass
	for _, field := range strings.Fields(printedAction.ReplaceAllString(text, printed)) {
		switch cut := strings.Index(field, printed); {
		case cut < 0:
			named = append(named, namedClass{name: field})
		case cut > 0:
			named = append(named, namedClass{name: field[:cut], prefix: true})
		}
	}
	return named
}

// drawnClasses reads the classes a stylesheet's selectors name: the text before each {, outside
// comments and strings, whatever a ; or a } closed before it, so a declaration's value is never read.
func drawnClasses(css string) map[string]bool {
	drawn := map[string]bool{}
	var prelude strings.Builder
	for i := 0; i < len(css); i++ {
		switch c := css[i]; {
		case strings.HasPrefix(css[i:], "/*"):
			end := strings.Index(css[i+2:], "*/")
			if end < 0 {
				return drawn
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
			prelude.WriteString(" ")
			i = j
		case c == '{':
			if p := strings.TrimSpace(prelude.String()); !strings.HasPrefix(p, "@") {
				for _, name := range selectorClasses(p) {
					drawn[name] = true
				}
			}
			prelude.Reset()
		case c == ';' || c == '}':
			prelude.Reset()
		case c == '\\' && i+1 < len(css):
			prelude.WriteByte(c)
			prelude.WriteByte(css[i+1])
			i++
		default:
			prelude.WriteByte(c)
		}
	}
	return drawn
}

// selectorClasses reads the class names a selector list names, each decoded from its CSS escapes.
func selectorClasses(selector string) []string {
	var names []string
	for i := 0; i < len(selector); i++ {
		if selector[i] != '.' {
			continue
		}
		name, next := cssIdent(selector, i+1)
		if name != "" {
			names = append(names, name)
		}
		i = next - 1
	}
	return names
}

// cssIdent reads the identifier at s[i:], decoding escapes (a backslash and up to six hex digits,
// then one optional space, or a backslash and any other character), and returns it and where it ends.
func cssIdent(s string, i int) (string, int) {
	var b strings.Builder
	for i < len(s) {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			j := i + 1
			for j < len(s) && j < i+7 && isHexDigit(s[j]) {
				j++
			}
			if j > i+1 {
				code, _ := strconv.ParseUint(s[i+1:j], 16, 32)
				b.WriteRune(rune(code))
				if j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\n') {
					j++
				}
				i = j
				continue
			}
			_, size := utf8.DecodeRuneInString(s[i+1:])
			b.WriteString(s[i+1 : i+1+size])
			i += 1 + size
		case c == '-' || c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80:
			b.WriteByte(c)
			i++
		default:
			return b.String(), i
		}
	}
	return b.String(), i
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
