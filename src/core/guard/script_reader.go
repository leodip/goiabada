package guard

import (
	"html"
	"io/fs"
	"strings"
)

// The one reader of the code a server serves, shared by AssertNoHTMLSinks and the admin console's
// rule for its dialog builder, so the two read the same code the same way (#120). The reading is
// lexical, over a small JavaScript tokenizer: no JavaScript runs in any tier, and a parser is a
// dependency neither module carries.
//
// It reads every place a page hands text to the JavaScript parser: a .js file whole; in a .html
// file every <script> element's body, every on... attribute's value and every javascript: URL, an
// attribute's value with its character references decoded, as the browser decodes it before
// compiling it. In a page a template action is one unit wherever it stands, since its own quotes
// are the template's and not the script's. Strings, comments and regex literals are units, so a sink
// named in a comment or a message string is not one. A template literal's text is a unit and its
// ${...} interpolations are code, read like any other. A member named by a fixed string,
// el["innerHTML"] or el[`innerHTML`], reads as el.innerHTML does, so a rule written for the dotted
// spelling holds the computed one too.
//
// Its boundary: a name assembled at run time, el["inner" + "HTML"], or a sink reached through
// Reflect or a function held in a variable, is beyond a lexical reading.

// ScriptKind is what a ScriptToken is.
type ScriptKind int

const (
	// ScriptEnd is the zero token, past the end of a script.
	ScriptEnd ScriptKind = iota
	// ScriptIdent is an identifier or a keyword.
	ScriptIdent
	// ScriptPunct is an operator or a bracket; a run of operator characters is one token.
	ScriptPunct
	// ScriptString is a '...' or "..." literal; Text is its contents.
	ScriptString
	// ScriptTemplate is one stretch of a template literal's text, between its backticks and its
	// interpolations; the interpolations themselves are tokens of their own.
	ScriptTemplate
	// ScriptValue is a number, a regex literal or a template action outside a string.
	ScriptValue
)

// ScriptToken is one token of a Script.
type ScriptToken struct {
	Kind ScriptKind
	Text string
	// Line is the line of the file the token is on, from one.
	Line int
	// Offset is the token's byte offset in the code it was read from.
	Offset int
	// Newline records a line break between this token and the one before it.
	Newline bool
	// Actions are the template actions inside a string or a template literal's text, in a page.
	Actions []string
}

// Is reports whether t is of kind and spelled text.
func (t ScriptToken) Is(kind ScriptKind, text string) bool { return t.Kind == kind && t.Text == text }

// Script is the code of one place a served file hands text to the JavaScript parser: a .js file,
// a <script> element, an on... attribute or a javascript: URL.
type Script struct {
	// Path is the file as the walked fs.FS spells it.
	Path   string
	Tokens []ScriptToken
	file   string
}

// LineText returns line n of the file the script is in, trimmed.
func (s Script) LineText(n int) string {
	lines := strings.Split(s.file, "\n")
	if n < 1 || n > len(lines) {
		return ""
	}
	return strings.TrimSpace(lines[n-1])
}

// ReadScripts walks fsys and returns the code of every .html and .js file in it, with how many such
// files it read, so a caller can tell "nothing to report" from "nothing was read".
func ReadScripts(fsys fs.FS) ([]Script, int, error) {
	var scripts []Script
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
		src := string(b)
		if !page {
			scripts = append(scripts, Script{Path: p, Tokens: TokenizeScript(src), file: src})
			return nil
		}
		for _, c := range pageCode(src) {
			scripts = append(scripts, Script{Path: p, Tokens: tokenizeScript(c.code, c.line, true), file: src})
		}
		return nil
	})
	return scripts, n, err
}

// TokenizeScript splits the source of a .js file into tokens, dropping whitespace and comments.
func TokenizeScript(src string) []ScriptToken {
	return tokenizeScript(src, 1, false)
}

// pageCodeSpan is one stretch of code in a page, and the line it starts on.
type pageCodeSpan struct {
	code string
	line int
}

// pageCode returns the code in a page: every <script> element's body, every on... attribute's value
// and every javascript: URL, the last two decoded. Template actions and comments, of the template
// and of the markup, are skipped as units.
func pageCode(src string) []pageCodeSpan {
	var spans []pageCodeSpan
	lineAt := func(i int) int { return strings.Count(src[:i], "\n") + 1 }
	action := func(i int) int {
		if !strings.HasPrefix(src[i:], "{{") {
			return -1
		}
		if k := strings.Index(src[i:], "}}"); k >= 0 {
			return i + k + 2
		}
		return len(src)
	}
	space := func(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' }

	for i := 0; i < len(src); {
		switch {
		case action(i) >= 0:
			i = action(i)
		case strings.HasPrefix(src[i:], "<!--"):
			if k := strings.Index(src[i:], "-->"); k >= 0 {
				i += k + 3
			} else {
				i = len(src)
			}
		case src[i] == '<' && i+1 < len(src) && isTagStart(src[i+1]):
			j := i + 1
			for j < len(src) && (isTagStart(src[j]) || src[j] >= '0' && src[j] <= '9' || src[j] == '-') {
				j++
			}
			tag := strings.ToLower(src[i+1 : j])
			for j < len(src) && src[j] != '>' {
				if k := action(j); k >= 0 {
					j = k
					continue
				}
				if space(src[j]) || src[j] == '/' {
					j++
					continue
				}
				ns := j
				for j < len(src) && !space(src[j]) && src[j] != '=' && src[j] != '>' && action(j) < 0 {
					j++
				}
				name := strings.ToLower(src[ns:j])
				for j < len(src) && space(src[j]) {
					j++
				}
				if j >= len(src) || src[j] != '=' {
					continue
				}
				j++
				for j < len(src) && space(src[j]) {
					j++
				}
				var value string
				vs := j
				if j < len(src) && (src[j] == '"' || src[j] == '\'') {
					q := src[j]
					vs = j + 1
					j = vs
					for j < len(src) && src[j] != q {
						if k := action(j); k >= 0 {
							j = k
							continue
						}
						j++
					}
					value = src[vs:min(j, len(src))]
					j = min(j+1, len(src))
				} else {
					for j < len(src) && !space(src[j]) && src[j] != '>' {
						if k := action(j); k >= 0 {
							j = k
							continue
						}
						j++
					}
					value = src[vs:min(j, len(src))]
				}
				value = html.UnescapeString(value)
				if strings.HasPrefix(name, "on") {
					spans = append(spans, pageCodeSpan{code: value, line: lineAt(vs)})
				} else if trimmed := strings.TrimLeft(value, " \t\r\n\f"); len(trimmed) >= len("javascript:") &&
					strings.EqualFold(trimmed[:len("javascript:")], "javascript:") {
					spans = append(spans, pageCodeSpan{code: trimmed[len("javascript:"):], line: lineAt(vs)})
				}
			}
			j = min(j+1, len(src))
			if tag == "script" {
				end := strings.Index(strings.ToLower(src[j:]), "</script")
				if end < 0 {
					end = len(src) - j
				}
				spans = append(spans, pageCodeSpan{code: src[j : j+end], line: lineAt(j)})
				j += end
			}
			i = j
		default:
			i++
		}
	}
	return spans
}

func isTagStart(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// regexAfter lists the keywords after which a "/" opens a regex literal rather than dividing, and
// after which a "[" opens an array rather than naming a member.
var regexAfter = map[string]bool{"return": true, "typeof": true, "case": true, "do": true, "else": true,
	"in": true, "of": true, "new": true, "delete": true, "void": true, "throw": true, "instanceof": true,
	"yield": true, "await": true}

// scriptLexer holds the state of one tokenizeScript.
type scriptLexer struct {
	src     string
	page    bool
	i       int
	line    int
	newline bool
	toks    []ScriptToken
	// depth counts the braces open; holes holds, for each template interpolation open, the depth
	// its closing brace returns to.
	depth int
	holes []int
}

// tokenizeScript splits code into tokens, dropping whitespace and comments; firstLine is the line
// of the file code starts on, and page says whether template actions are read as units.
func tokenizeScript(code string, firstLine int, page bool) []ScriptToken {
	l := &scriptLexer{src: code, page: page, line: firstLine}
	for l.i < len(l.src) {
		l.next()
	}
	return memberNames(l.toks)
}

func (l *scriptLexer) push(t ScriptToken) {
	t.Newline = l.newline
	l.newline = false
	l.toks = append(l.toks, t)
}

// advance moves past src[i:to], counting the lines it crosses.
func (l *scriptLexer) advance(to int) {
	to = min(to, len(l.src))
	if n := strings.Count(l.src[l.i:to], "\n"); n > 0 {
		l.line += n
		l.newline = true
	}
	l.i = to
}

// action returns the end of the template action at j, or -1 when there is none.
func (l *scriptLexer) action(j int) int {
	if !l.page || !strings.HasPrefix(l.src[j:], "{{") {
		return -1
	}
	k := strings.Index(l.src[j:], "}}")
	if k < 0 {
		return -1
	}
	return j + k + 2
}

func (l *scriptLexer) regexAllowed() bool {
	if len(l.toks) == 0 {
		return true
	}
	last := l.toks[len(l.toks)-1]
	switch last.Kind {
	case ScriptIdent:
		return regexAfter[last.Text]
	case ScriptPunct:
		return last.Text != ")" && last.Text != "]"
	}
	return false
}

// next reads one token, or skips one stretch of whitespace or one comment.
func (l *scriptLexer) next() {
	src, i := l.src, l.i
	c := src[i]
	at := func(kind ScriptKind, end int) {
		l.push(ScriptToken{Kind: kind, Text: src[i:end], Line: l.line, Offset: i})
		l.advance(end)
	}
	switch {
	case c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f':
		l.advance(i + 1)
	case l.action(i) >= 0:
		at(ScriptValue, l.action(i))
	case strings.HasPrefix(src[i:], "//"):
		k := strings.IndexByte(src[i:], '\n')
		if k < 0 {
			k = len(src) - i
		}
		l.advance(i + k)
	case strings.HasPrefix(src[i:], "/*"):
		k := strings.Index(src[i+2:], "*/")
		if k < 0 {
			l.advance(len(src))
		} else {
			l.advance(i + 2 + k + 2)
		}
	case c == '"' || c == '\'':
		t := ScriptToken{Kind: ScriptString, Line: l.line, Offset: i}
		j := i + 1
		var text strings.Builder
		for j < len(src) && src[j] != c && src[j] != '\n' {
			if k := l.action(j); k >= 0 {
				t.Actions = append(t.Actions, src[j:k])
				text.WriteString(src[j:k])
				j = k
				continue
			}
			if src[j] == '\\' && j+1 < len(src) {
				text.WriteByte(src[j])
				j++
			}
			text.WriteByte(src[j])
			j++
		}
		t.Text = text.String()
		l.push(t)
		l.advance(j + 1)
	case c == '`':
		l.template(i + 1)
	case c == '/' && l.regexAllowed():
		j, class := i+1, false
		for j < len(src) && src[j] != '\n' && (class || src[j] != '/') {
			switch src[j] {
			case '\\':
				j++
			case '[':
				class = true
			case ']':
				class = false
			}
			j++
		}
		j++
		for j < len(src) && isIdentByte(src[j]) {
			j++
		}
		at(ScriptValue, j)
	case isIdentByte(c):
		j := i
		for j < len(src) && isIdentByte(src[j]) {
			j++
		}
		kind := ScriptIdent
		if c >= '0' && c <= '9' {
			kind = ScriptValue
		}
		at(kind, j)
	case strings.IndexByte("=!<>+-*%&|^?~:", c) >= 0:
		j := i
		for j < len(src) && strings.IndexByte("=!<>+-*%&|^?~:", src[j]) >= 0 {
			j++
		}
		at(ScriptPunct, j)
	case c == '{':
		l.depth++
		at(ScriptPunct, i+1)
	case c == '}':
		l.depth--
		if n := len(l.holes); n > 0 && l.holes[n-1] == l.depth {
			l.holes = l.holes[:n-1]
			l.template(i + 1)
			return
		}
		at(ScriptPunct, i+1)
	default:
		at(ScriptPunct, i+1)
	}
}

// template reads one stretch of a template literal's text, from j to its closing backtick or to the
// ${ of its next interpolation, whose code the lexer then reads as code until its closing brace.
func (l *scriptLexer) template(j int) {
	src := l.src
	t := ScriptToken{Kind: ScriptTemplate, Line: l.line, Offset: l.i}
	var text strings.Builder
	for j < len(src) {
		if k := l.action(j); k >= 0 {
			t.Actions = append(t.Actions, src[j:k])
			text.WriteString(src[j:k])
			j = k
			continue
		}
		switch {
		case src[j] == '\\' && j+1 < len(src):
			text.WriteString(src[j : j+2])
			j += 2
			continue
		case src[j] == '`':
			t.Text = text.String()
			l.push(t)
			l.advance(j + 1)
			return
		case strings.HasPrefix(src[j:], "${"):
			t.Text = text.String()
			l.push(t)
			l.holes = append(l.holes, l.depth)
			l.depth++
			l.advance(j + 2)
			return
		}
		text.WriteByte(src[j])
		j++
	}
	t.Text = text.String()
	l.push(t)
	l.advance(len(src))
}

// memberNames rewrites each member named by a fixed string, x["name"] or x[`name`], as x.name, so
// a rule reads one spelling. A "[" after anything that cannot end an operand opens an array, and is
// left alone.
func memberNames(toks []ScriptToken) []ScriptToken {
	out := make([]ScriptToken, 0, len(toks))
	for i := 0; i < len(toks); i++ {
		if i+2 < len(toks) && toks[i].Is(ScriptPunct, "[") && toks[i+2].Is(ScriptPunct, "]") &&
			(toks[i+1].Kind == ScriptString || toks[i+1].Kind == ScriptTemplate) &&
			len(toks[i+1].Actions) == 0 && isIdentName(toks[i+1].Text) && len(out) > 0 && endsOperand(out[len(out)-1]) {
			name := toks[i+1]
			out = append(out,
				ScriptToken{Kind: ScriptPunct, Text: ".", Line: toks[i].Line, Offset: toks[i].Offset, Newline: toks[i].Newline},
				ScriptToken{Kind: ScriptIdent, Text: name.Text, Line: name.Line, Offset: name.Offset})
			i += 2
			continue
		}
		out = append(out, toks[i])
	}
	return out
}

// endsOperand reports whether t can end the operand a following "[" indexes.
func endsOperand(t ScriptToken) bool {
	switch t.Kind {
	case ScriptIdent:
		return !regexAfter[t.Text]
	case ScriptPunct:
		return t.Text == ")" || t.Text == "]"
	case ScriptString, ScriptTemplate, ScriptValue:
		return true
	}
	return false
}

func isIdentName(s string) bool {
	if s == "" || s[0] >= '0' && s[0] <= '9' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isIdentByte(s[i]) {
			return false
		}
	}
	return true
}

func isIdentByte(c byte) bool {
	return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c >= 0x80
}
