package web

import (
	"context"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
	"github.com/leodip/goiabada/core/i18n"
)

// The console's rule for its dialog markup builder (#120, decision 1). showModalDialog parses a
// message as HTML only when it is the result of dialogMarkup or dialogMarkupFormat in
// static/utils.js, which escape every value they are handed. What makes that safe is that the
// markup itself comes from nowhere but the catalog, which carries no data. So every call to either
// builder names its markup as literals: dialogMarkup's first argument is an array of quoted strings
// whose template actions are all catalog lookups, the parts the values go between, and
// dialogMarkupFormat's first argument is a quoted client-side catalog key. A builder named any
// other way, aliased or passed along, is refused too, because its arguments can no longer be read.
//
// Beside it, a dialog message names no catalog text carrying markup in any locale outside a
// builder call: not as one plain catalog literal, not as t("key") or tFormat("key", ...), and not
// spliced around a value. showModalDialog shows a message its builders did not build as text, so
// such a message would show its accent span as tags; a message that needs its markup goes through
// the builder, which also escapes the values that join it.
//
// This rule is the console's and lives here rather than in core/guard, since the auth server has no
// builder. It follows the guard shape all the same: a finder, and a reporting half driven through
// guard.Run. The reading is lexical, over the same embedded bytes the browser is served. It skips
// comments and reads strings, template literals and template actions as units; a regex literal
// holding a quote would throw it off, and none exists.

// dialogBuilders are the two builders, each with what its first argument must be.
var dialogBuilders = map[string]string{
	"dialogMarkup":       "an array of quoted catalog literals",
	"dialogMarkupFormat": "a quoted client-side catalog key",
}

// dialogFault is one call the rule refuses, located.
type dialogFault struct {
	path string
	line int
	why  string
}

// dialogCalls counts what a walk reached, so the reporting half can tell a clean tree from one in
// which it read nothing.
type dialogCalls struct {
	files, dialogs, builders int
}

// markupIn reports whether the catalog value of key, in any locale, carries markup.
type markupIn func(key string) bool

// markupRe matches the start of a tag or an entity, the two things that make a catalog value
// markup rather than text.
var markupRe = regexp.MustCompile(`<[a-zA-Z/!]|&[a-zA-Z#0-9]+;`)

// catalogMarkup reads the real catalogs, in every locale the console ships.
func catalogMarkup(key string) bool {
	for _, tag := range []string{"en", "pt-BR"} {
		ctx := i18n.WithLocale(context.Background(), true, tag)
		if markupRe.MatchString(i18n.Raw(ctx, key)) {
			return true
		}
	}
	return false
}

// TestDialogMessages_MarkupOnlyThroughTheBuilder holds every page and script this server serves to
// the rule above.
func TestDialogMessages_MarkupOnlyThroughTheBuilder(t *testing.T) {
	assertDialogMessages(t, catalogMarkup, templateFS, staticFS)
}

// assertDialogMessages is the reporting half. A walk that reached no file, no dialog or no builder
// call is fatal, because every rule passes vacuously over nothing.
func assertDialogMessages(r guard.Reporter, markup markupIn, trees ...fs.FS) {
	r.Helper()

	var faults []dialogFault
	var total dialogCalls
	for _, tree := range trees {
		f, n, err := findDialogFaults(tree, markup)
		if err != nil {
			r.Fatalf("walking for pages and scripts: %v", err)
		}
		if n.files == 0 {
			r.Fatalf("reached no .html or .js file in one of the trees; this rule is checking nothing")
		}
		faults = append(faults, f...)
		total.dialogs += n.dialogs
		total.builders += n.builders
	}
	for _, f := range faults {
		r.Errorf("%s:%d: %s (#120)", f.path, f.line, f.why)
	}
	if total.dialogs == 0 || total.builders == 0 {
		r.Fatalf("reached %d showModalDialog calls and %d builder calls; the dialog or its builder "+
			"was renamed, so this rule is checking nothing", total.dialogs, total.builders)
	}
}

// scriptElementRe matches one <script> element's body in a page.
var scriptElementRe = regexp.MustCompile(`(?is)<script\b[^>]*>(.*?)</script\s*>`)

// catalogKeyRe matches a catalog lookup with no arguments and captures its key. It is the one
// template action a builder's part, or a plain dialog message, may carry.
var catalogKeyRe = regexp.MustCompile(`^\{\{-?\s*T\s+\$?\.ctx\s+"([^"\\]*)"\s*-?\}\}$`)

// findDialogFaults walks fsys and returns every builder call and plain dialog message the rule
// refuses.
func findDialogFaults(fsys fs.FS, markup markupIn) ([]dialogFault, dialogCalls, error) {
	var faults []dialogFault
	var n dialogCalls
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
		n.files++
		src := string(b)
		spans := [][]int{{0, len(src)}}
		if page {
			spans = nil
			for _, m := range scriptElementRe.FindAllStringSubmatchIndex(src, -1) {
				spans = append(spans, m[2:4])
			}
		}
		for _, s := range spans {
			toks := lexScript(src, s[0], s[1], page)
			faults = append(faults, dialogFaultsIn(p, src, toks, markup, &n)...)
		}
		return nil
	})
	return faults, n, err
}

// dialogFaultsIn applies the rule to one script's tokens.
func dialogFaultsIn(path, src string, toks []scriptToken, markup markupIn, n *dialogCalls) []dialogFault {
	var faults []dialogFault
	at := func(i int) scriptToken {
		if i >= 0 && i < len(toks) {
			return toks[i]
		}
		return scriptToken{}
	}
	report := func(t scriptToken, why string) {
		faults = append(faults, dialogFault{path: path, line: strings.Count(src[:t.at], "\n") + 1, why: why})
	}

	for i, t := range toks {
		if t.kind != tokIdent {
			continue
		}
		if want, ok := dialogBuilders[t.text]; ok {
			if at(i-1).is(tokIdent, "function") {
				continue
			}
			if !at(i+1).is(tokPunct, "(") {
				report(t, t.text+" is named other than in a call, so its parts cannot be read")
				continue
			}
			n.builders++
			var ok bool
			if t.text == "dialogMarkup" {
				ok = catalogPartsArray(toks, i+2)
			} else {
				arg := at(i + 2)
				ok = arg.kind == tokString && len(arg.actions) == 0 &&
					(at(i+3).is(tokPunct, ",") || at(i+3).is(tokPunct, ")"))
			}
			if !ok {
				report(t, t.text+"'s first argument is not "+want+"; the markup a builder renders "+
					"comes from the catalog, and every value goes after it, to be escaped")
			}
			continue
		}
		if t.text != "showModalDialog" || at(i-1).is(tokIdent, "function") || !at(i+1).is(tokPunct, "(") {
			continue
		}
		n.dialogs++
		for _, key := range unbuiltMessageKeys(callArgument(toks, i+2, 2)) {
			if markup(key) {
				report(t, fmt.Sprintf("the dialog message carries the catalog text of %q, which "+
					"carries markup, outside the builder; the dialog shows that as text, so build "+
					"it with dialogMarkup, which keeps the markup and escapes whatever joins it", key))
				break
			}
		}
	}
	return faults
}

// catalogPartsArray reports whether toks[i:] opens with an array of one or more quoted strings
// whose template actions are all catalog lookups, followed by the end of the argument.
func catalogPartsArray(toks []scriptToken, i int) bool {
	if i >= len(toks) || !toks[i].is(tokPunct, "[") {
		return false
	}
	i++
	parts := 0
	for i < len(toks) {
		t := toks[i]
		if t.kind != tokString {
			break
		}
		for _, a := range t.actions {
			if !catalogKeyRe.MatchString(a) {
				return false
			}
		}
		parts++
		i++
		if i < len(toks) && toks[i].is(tokPunct, ",") {
			i++
		}
	}
	return parts > 0 && i+1 < len(toks) && toks[i].is(tokPunct, "]") &&
		(toks[i+1].is(tokPunct, ",") || toks[i+1].is(tokPunct, ")"))
}

// callArgument returns the tokens of argument n (from zero) of the call whose arguments start at
// toks[i], or nil when the call has fewer.
func callArgument(toks []scriptToken, i, n int) []scriptToken {
	depth, start, arg := 0, i, 0
	for j := i; j < len(toks); j++ {
		t := toks[j]
		if t.kind != tokPunct {
			continue
		}
		switch t.text {
		case "(", "[", "{":
			depth++
		case ")", "]", "}":
			if depth == 0 {
				if arg == n {
					return toks[start:j]
				}
				return nil
			}
			depth--
		case ",":
			if depth == 0 {
				if arg == n {
					return toks[start:j]
				}
				arg++
				start = j + 1
			}
		}
	}
	return nil
}

// unbuiltMessageKeys returns the catalog keys a message names outside any builder call: the
// catalog lookups in its quoted literals, and the key of each t("key") or tFormat("key", ...).
// A builder call's own arguments are the builder rule's, and a message held in a variable names
// none.
func unbuiltMessageKeys(arg []scriptToken) []string {
	var keys []string
	for i := 0; i < len(arg); i++ {
		t := arg[i]
		if _, ok := dialogBuilders[t.text]; ok && t.kind == tokIdent && i+1 < len(arg) && arg[i+1].is(tokPunct, "(") {
			i = closingParen(arg, i+1)
			continue
		}
		if t.kind == tokIdent && (t.text == "t" || t.text == "tFormat") && i+2 < len(arg) &&
			arg[i+1].is(tokPunct, "(") && arg[i+2].kind == tokString && len(arg[i+2].actions) == 0 {
			keys = append(keys, arg[i+2].text)
			i += 2
			continue
		}
		if t.kind == tokString {
			for _, a := range t.actions {
				if m := catalogKeyRe.FindStringSubmatch(a); m != nil {
					keys = append(keys, m[1])
				}
			}
		}
	}
	return keys
}

// closingParen returns the index of the parenthesis closing the one at toks[open], or the last
// index when it is never closed.
func closingParen(toks []scriptToken, open int) int {
	depth := 0
	for j := open; j < len(toks); j++ {
		switch {
		case toks[j].is(tokPunct, "("):
			depth++
		case toks[j].is(tokPunct, ")"):
			depth--
			if depth == 0 {
				return j
			}
		}
	}
	return len(toks) - 1
}

type scriptTokenKind int

const (
	tokEnd scriptTokenKind = iota
	tokIdent
	tokPunct
	tokString // '...' or "...": text is the contents, actions the template actions in it
	tokOther  // a template literal, a number or a template action outside a string
)

type scriptToken struct {
	kind    scriptTokenKind
	text    string
	at      int
	actions []string
}

func (t scriptToken) is(kind scriptTokenKind, text string) bool {
	return t.kind == kind && t.text == text
}

// lexScript splits src[start:end] into tokens, dropping whitespace and comments. In a page a
// template action is one unit wherever it stands, since its own quotes are the template's.
func lexScript(src string, start, end int, page bool) []scriptToken {
	var toks []scriptToken
	action := func(j int) int {
		if !page || !strings.HasPrefix(src[j:end], "{{") {
			return -1
		}
		k := strings.Index(src[j:end], "}}")
		if k < 0 {
			return -1
		}
		return j + k + 2
	}
	for i := start; i < end; {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
		case action(i) >= 0:
			j := action(i)
			toks = append(toks, scriptToken{kind: tokOther, text: src[i:j], at: i})
			i = j
		case strings.HasPrefix(src[i:end], "//"):
			for i < end && src[i] != '\n' {
				i++
			}
		case strings.HasPrefix(src[i:end], "/*"):
			if k := strings.Index(src[i+2:end], "*/"); k >= 0 {
				i += k + 4
			} else {
				i = end
			}
		case c == '"' || c == '\'' || c == '`':
			t := scriptToken{kind: tokString, at: i}
			if c == '`' {
				t.kind = tokOther
			}
			var text strings.Builder
			j := i + 1
			for j < end && src[j] != c {
				if k := action(j); k >= 0 {
					t.actions = append(t.actions, src[j:k])
					text.WriteString(src[j:k])
					j = k
					continue
				}
				if src[j] == '\\' && j+1 < end {
					text.WriteByte(src[j])
					j++
				}
				text.WriteByte(src[j])
				j++
			}
			t.text = text.String()
			toks = append(toks, t)
			i = j + 1
		case isScriptIdentByte(c):
			j := i
			for j < end && isScriptIdentByte(src[j]) {
				j++
			}
			kind := tokIdent
			if c >= '0' && c <= '9' {
				kind = tokOther
			}
			toks = append(toks, scriptToken{kind: kind, text: src[i:j], at: i})
			i = j
		default:
			toks = append(toks, scriptToken{kind: tokPunct, text: src[i : i+1], at: i})
			i++
		}
	}
	return toks
}

func isScriptIdentByte(c byte) bool {
	return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c >= 0x80
}

// renderDialogFaults renders findings as "<path>:<line>" so a failure names what was missed or
// over-matched.
func renderDialogFaults(faults []dialogFault) []string {
	out := make([]string, 0, len(faults))
	for _, f := range faults {
		out = append(out, fmt.Sprintf("%s:%d", f.path, f.line))
	}
	sort.Strings(out)
	return out
}
