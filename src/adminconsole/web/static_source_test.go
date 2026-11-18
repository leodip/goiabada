package web

import (
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

// Readers of the served static/utils.js: the static lint and the scripts the unit tier runs through
// Node both use them, so they live outside the lint file, which builds only without the race
// detector.

// utilsJS returns the real embedded static/utils.js, the file the browser is served.
//
// Reading it through staticFS rather than off disk is deliberate: it is the same byte stream
// StaticFS() hands the router, so a file that stopped being embedded fails here rather than
// passing a lint and then 404ing in production.
func utilsJS(t *testing.T) string {
	t.Helper()
	b, err := staticFS.ReadFile("static/utils.js")
	if err != nil {
		t.Fatalf("reading static/utils.js: %v", err)
	}
	return string(b)
}

// functionBody returns the parameter list and the body of the one function declared as name in the
// JavaScript source src, each without its brackets, read through the tokenizer so its indentation
// does not matter.
func functionBody(src, name string) (params, body string, ok bool) {
	toks := guard.TokenizeScript(src)
	for i := 0; i+2 < len(toks); i++ {
		if !toks[i].Is(guard.ScriptIdent, "function") || !toks[i+1].Is(guard.ScriptIdent, name) ||
			!toks[i+2].Is(guard.ScriptPunct, "(") {
			continue
		}
		closeParams := matching(toks, i+2)
		if closeParams < 0 || closeParams+1 >= len(toks) || !toks[closeParams+1].Is(guard.ScriptPunct, "{") {
			return "", "", false
		}
		closeBody := matching(toks, closeParams+1)
		if closeBody < 0 {
			return "", "", false
		}
		return src[toks[i+2].Offset+1 : toks[closeParams].Offset],
			src[toks[closeParams+1].Offset+1 : toks[closeBody].Offset], true
	}
	return "", "", false
}

// matching returns the index of the bracket closing the one at toks[open], or -1.
func matching(toks []guard.ScriptToken, open int) int {
	closer := map[string]string{"(": ")", "[": "]", "{": "}"}[toks[open].Text]
	depth := 0
	for j := open; j < len(toks); j++ {
		switch {
		case toks[j].Is(guard.ScriptPunct, toks[open].Text):
			depth++
		case toks[j].Is(guard.ScriptPunct, closer):
			depth--
			if depth == 0 {
				return j
			}
		}
	}
	return -1
}
