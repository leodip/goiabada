package guard

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// AssertClassesAreDrawn holds every class a page or a script names to a rule in css, the
// application's generated main.css (#617). Tailwind writes a rule only for a utility it reads in a
// template or a script, and ui.css only for the components it defines, so a class that has no rule
// is a misspelling, a leftover of a stylesheet that is gone, or a utility built where Tailwind
// cannot read it, and the page is drawn as though it were not there, which nothing else notices.
//
// It reads every class attribute of every .html file in each tree, and every class a .js file
// writes: a string assigned to className, or handed to classList's add, remove, toggle, contains or
// replace. In a page a control action, {{if}}, {{else}} or {{end}}, writes nothing, so each
// branch's classes are read; an action that prints a value stands for text the guard cannot read,
// so a class it writes whole is not read, and one it completes, theme-swatch-{{ . }}, is a prefix,
// held to some class beginning with it. In a script, a string a + continues ends in a prefix the
// same way. Its boundary: a class a handler hands a template, or a script builds any other way, is
// beyond it.
//
// Each tree is walked from its root; both servers pass their //go:embed sets. A tree that reaches
// no .html or .js file, and a stylesheet that defines no class, are fatal, because every class
// would pass or fail over nothing.
func AssertClassesAreDrawn(t *testing.T, css []byte, trees ...fs.FS) {
	t.Helper()

	assertClassesAreDrawn(t, css, trees...)
}

// assertClassesAreDrawn is the reporting half, failing through a Reporter so a rule test can drive
// it against fixture trees. See Reporter in guard.go.
func assertClassesAreDrawn(r Reporter, css []byte, trees ...fs.FS) {
	r.Helper()

	drawn := drawnClasses(css)
	if len(drawn) == 0 {
		r.Fatalf("the stylesheet defines no class; this guard is checking nothing")
	}
	for _, tree := range trees {
		named, n, err := findNamedClasses(tree)
		if err != nil {
			r.Fatalf("walking for pages and scripts: %v", err)
		}
		if n == 0 {
			r.Fatalf("reached no .html or .js file in one of the trees; this guard is checking nothing")
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
}

// namedClass is a class a page or a script names, or, with prefix, the start of one it completes
// with a value.
type namedClass struct {
	path   string
	line   int
	name   string
	prefix bool
}

// cssClass is a class selector, its characters escaped as CSS escapes them: sm\:flex, w-1\/2.
var cssClass = regexp.MustCompile(`\.((?:\\.|[A-Za-z0-9_-])+)`)

var cssEscape = regexp.MustCompile(`\\(.)`)

func drawnClasses(css []byte) map[string]bool {
	drawn := map[string]bool{}
	for _, m := range cssClass.FindAllSubmatch(css, -1) {
		drawn[cssEscape.ReplaceAllString(string(m[1]), "$1")] = true
	}
	return drawn
}

func drawsPrefix(drawn map[string]bool, prefix string) bool {
	for name := range drawn {
		if len(name) > len(prefix) && strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func findNamedClasses(fsys fs.FS) ([]namedClass, int, error) {
	var named []namedClass
	n := 0
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		page := strings.HasSuffix(p, ".html")
		if d.IsDir() || (!page && !strings.HasSuffix(p, ".js")) {
			return nil
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		n++
		if page {
			named = append(named, pageClasses(p, string(b))...)
		} else {
			named = append(named, scriptClasses(p, TokenizeScript(string(b)))...)
		}
		return nil
	})
	return named, n, err
}

// classAttr is the start of a class attribute's value, after whitespace, so data-class is not one.
var classAttr = regexp.MustCompile(`\sclass\s*=\s*"`)

// printed stands for the text an action prints, inside a class it completes.
const printed = "\x00"

// pageClasses reads the classes of each class attribute in a page.
func pageClasses(path, src string) []namedClass {
	var named []namedClass
	for _, at := range classAttr.FindAllStringIndex(src, -1) {
		line := strings.Count(src[:at[0]], "\n") + 1
		var value strings.Builder
		for j := at[1]; j < len(src) && src[j] != '"'; {
			if strings.HasPrefix(src[j:], "{{") {
				end := strings.Index(src[j:], "}}")
				if end < 0 {
					break
				}
				if isControlAction(src[j+2 : j+end]) {
					value.WriteByte(' ')
				} else {
					value.WriteString(printed)
				}
				j += end + 2
				continue
			}
			value.WriteByte(src[j])
			j++
		}
		for _, field := range strings.Fields(value.String()) {
			cut := strings.Index(field, printed)
			switch {
			case cut < 0:
				named = append(named, namedClass{path: path, line: line, name: field})
			case cut > 0:
				named = append(named, namedClass{path: path, line: line, name: field[:cut], prefix: true})
			}
		}
	}
	return named
}

// isControlAction reports whether a template action, its delimiters removed, writes nothing.
func isControlAction(action string) bool {
	action = strings.TrimSpace(strings.Trim(action, "-"))
	if strings.HasPrefix(action, "/*") {
		return true
	}
	word, _, _ := strings.Cut(action, " ")
	switch word {
	case "if", "else", "end", "with", "range", "break", "continue":
		return true
	}
	return false
}

var classListMethods = map[string]bool{"add": true, "remove": true, "toggle": true, "contains": true, "replace": true}

// scriptClasses reads the classes a script assigns to className or hands to classList.
func scriptClasses(path string, toks []ScriptToken) []namedClass {
	toks = memberNames(toks)
	at := func(i int) ScriptToken {
		if i < len(toks) {
			return toks[i]
		}
		return ScriptToken{}
	}
	var named []namedClass
	read := func(i int) {
		s := toks[i]
		fields := strings.Fields(s.Text)
		continued := at(i+1).Is(ScriptPunct, "+") && !strings.HasSuffix(s.Text, " ")
		for k, field := range fields {
			named = append(named, namedClass{path: path, line: s.Line, name: field, prefix: continued && k == len(fields)-1})
		}
	}
	for i := 0; i+1 < len(toks); i++ {
		if !toks[i].Is(ScriptPunct, ".") {
			continue
		}
		switch {
		case toks[i+1].Is(ScriptIdent, "className") && (at(i+2).Is(ScriptPunct, "=") || at(i+2).Is(ScriptPunct, "+=")) &&
			at(i+3).Kind == ScriptString:
			read(i + 3)
		case toks[i+1].Is(ScriptIdent, "classList") && at(i+2).Is(ScriptPunct, ".") && classListMethods[at(i+3).Text] &&
			at(i+4).Is(ScriptPunct, "("):
			depth := 0
		args:
			for j := i + 4; j < len(toks); j++ {
				t := toks[j]
				switch {
				case t.Kind == ScriptPunct && (t.Text == "(" || t.Text == "[" || t.Text == "{"):
					depth++
				case t.Kind == ScriptPunct && (t.Text == ")" || t.Text == "]" || t.Text == "}"):
					depth--
					if depth == 0 {
						break args
					}
				case t.Kind == ScriptString && depth == 1 && (toks[j-1].Is(ScriptPunct, "(") || toks[j-1].Is(ScriptPunct, ",")):
					read(j)
				}
			}
		}
	}
	return named
}
