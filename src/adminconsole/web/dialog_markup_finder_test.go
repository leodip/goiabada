package web

import (
	"fmt"
	"io/fs"
	"regexp"
	"sort"

	"github.com/leodip/goiabada/core/guard"
)

// The finder and reporting half of the dialog markup rule that dialog_markup_lint_test.go states and
// runs over the served tree. dialog_markup_rules_test.go drives them over fixtures, under the race
// detector as well, so they live outside the lint file, which builds only without it.

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

// catalogKeyRe matches a catalog lookup with no arguments and captures its key. It is the one
// template action a builder's part, or a plain dialog message, may carry.
var catalogKeyRe = regexp.MustCompile(`^\{\{-?\s*T\s+\$?\.ctx\s+"([^"\\]*)"\s*-?\}\}$`)

// builderHome is the file that declares the builders.
const builderHome = "static/utils.js"

// findDialogFaults walks fsys and returns every builder call and plain dialog message the rule
// refuses.
func findDialogFaults(fsys fs.FS, markup markupIn) ([]dialogFault, dialogCalls, error) {
	scripts, files, err := guard.ReadScripts(fsys)
	var faults []dialogFault
	n := dialogCalls{files: files}
	for _, s := range scripts {
		faults = append(faults, dialogFaultsIn(s.Path, s.Tokens, markup, &n)...)
	}
	return faults, n, err
}

// dialogFaultsIn applies the rule to one script's tokens.
func dialogFaultsIn(path string, toks []guard.ScriptToken, markup markupIn, n *dialogCalls) []dialogFault {
	var faults []dialogFault
	at := func(i int) guard.ScriptToken {
		if i >= 0 && i < len(toks) {
			return toks[i]
		}
		return guard.ScriptToken{}
	}
	report := func(t guard.ScriptToken, why string) {
		faults = append(faults, dialogFault{path: path, line: t.Line, why: why})
	}

	for i, t := range toks {
		if t.Kind != guard.ScriptIdent {
			continue
		}
		if want, ok := dialogBuilders[t.Text]; ok {
			if at(i-1).Is(guard.ScriptIdent, "function") {
				continue
			}
			if path == builderHome && (at(i-1).Is(guard.ScriptPunct, "{") || at(i-1).Is(guard.ScriptPunct, ",")) &&
				(at(i+1).Is(guard.ScriptPunct, ",") || at(i+1).Is(guard.ScriptPunct, "}")) {
				continue
			}
			if !at(i+1).Is(guard.ScriptPunct, "(") {
				report(t, t.Text+" is named other than in a call, so its parts cannot be read")
				continue
			}
			n.builders++
			var ok bool
			if t.Text == "dialogMarkup" {
				ok = catalogPartsArray(toks, i+2)
			} else {
				arg := at(i + 2)
				ok = arg.Kind == guard.ScriptString && len(arg.Actions) == 0 &&
					(at(i+3).Is(guard.ScriptPunct, ",") || at(i+3).Is(guard.ScriptPunct, ")"))
			}
			if !ok {
				report(t, t.Text+"'s first argument is not "+want+"; the markup a builder renders "+
					"comes from the catalog, and every value goes after it, to be escaped")
			}
			continue
		}
		if t.Text != "showModalDialog" || at(i-1).Is(guard.ScriptIdent, "function") || !at(i+1).Is(guard.ScriptPunct, "(") {
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
func catalogPartsArray(toks []guard.ScriptToken, i int) bool {
	if i >= len(toks) || !toks[i].Is(guard.ScriptPunct, "[") {
		return false
	}
	i++
	parts := 0
	for i < len(toks) {
		t := toks[i]
		if t.Kind != guard.ScriptString {
			break
		}
		for _, a := range t.Actions {
			if !catalogKeyRe.MatchString(a) {
				return false
			}
		}
		parts++
		i++
		if i < len(toks) && toks[i].Is(guard.ScriptPunct, ",") {
			i++
		}
	}
	return parts > 0 && i+1 < len(toks) && toks[i].Is(guard.ScriptPunct, "]") &&
		(toks[i+1].Is(guard.ScriptPunct, ",") || toks[i+1].Is(guard.ScriptPunct, ")"))
}

// callArgument returns the tokens of argument n (from zero) of the call whose arguments start at
// toks[i], or nil when the call has fewer.
func callArgument(toks []guard.ScriptToken, i, n int) []guard.ScriptToken {
	depth, start, arg := 0, i, 0
	for j := i; j < len(toks); j++ {
		t := toks[j]
		if t.Kind != guard.ScriptPunct {
			continue
		}
		switch t.Text {
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
func unbuiltMessageKeys(arg []guard.ScriptToken) []string {
	var keys []string
	for i := 0; i < len(arg); i++ {
		t := arg[i]
		if _, ok := dialogBuilders[t.Text]; ok && t.Kind == guard.ScriptIdent && i+1 < len(arg) && arg[i+1].Is(guard.ScriptPunct, "(") {
			i = closingParen(arg, i+1)
			continue
		}
		if t.Kind == guard.ScriptIdent && (t.Text == "t" || t.Text == "tFormat") && i+2 < len(arg) &&
			arg[i+1].Is(guard.ScriptPunct, "(") && arg[i+2].Kind == guard.ScriptString && len(arg[i+2].Actions) == 0 {
			keys = append(keys, arg[i+2].Text)
			i += 2
			continue
		}
		if t.Kind == guard.ScriptString {
			for _, a := range t.Actions {
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
func closingParen(toks []guard.ScriptToken, open int) int {
	depth := 0
	for j := open; j < len(toks); j++ {
		switch {
		case toks[j].Is(guard.ScriptPunct, "("):
			depth++
		case toks[j].Is(guard.ScriptPunct, ")"):
			depth--
			if depth == 0 {
				return j
			}
		}
	}
	return len(toks) - 1
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
