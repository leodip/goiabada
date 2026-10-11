package web

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/guard"
)

// The order a confirmation dialog answers in (#562, decision 2). Its buttons sit in a form whose
// method is dialog, so a click on one ran the page's callback and then let the form close the
// dialog. A callback that asked a second question opened it on the dialog still open, and the same
// click then closed it: the save behind the second question was dropped without asking. Every
// button therefore answers by preventing the form's default, closing the dialog, and only then
// running the callback, so a question asked from inside a callback opens on a closed dialog and
// stays open until answered.
//
// And every call sets both buttons. A button given no callback just closes the dialog; before, it
// kept whatever callback a previous call had left on it, so a "close" after a "yes/no" could still
// run the old Yes.
//
// Lexical, like the checks in static_lint_test.go, because no tier runs JavaScript: inside
// showModalDialog's body, an inner function whose returned handler calls preventDefault, then
// close on the dialog element, and only after both its callback; each button's onclick set once,
// to that function's answer for its own callback; and neither callback read anywhere else, since a
// read in a condition is what let a call without a callback leave the old one standing.

// dialogAnswerFaults returns what showModalDialog in the JavaScript source src does against the
// rule above, and false when src declares no showModalDialog this check can read.
func dialogAnswerFaults(src string) ([]string, bool) {
	params, body, ok := functionBody(src, "showModalDialog")
	if !ok {
		return nil, false
	}
	names := strings.Split(params, ",")
	if len(names) != 5 {
		return []string{"showModalDialog no longer takes (id, title, message, btn1callback, btn2callback); " +
			"update this check to name its callbacks"}, true
	}
	callbacks := map[string]string{"1": strings.TrimSpace(names[3]), "2": strings.TrimSpace(names[4])}

	toks := guard.TokenizeScript(body)
	var faults []string

	dialog := elementByID(toks, "_modalDialog")
	if dialog == "" {
		faults = append(faults, `showModalDialog holds no element got by id + "_modalDialog"; the answer cannot close it`)
	}

	// The answer: the inner function whose handler prevents the form's default.
	answer, prevent, closes, calls := "", -1, -1, []int(nil)
	for i := 0; i+2 < len(toks); i++ {
		if !toks[i].Is(guard.ScriptIdent, "function") || toks[i+1].Kind != guard.ScriptIdent ||
			!toks[i+2].Is(guard.ScriptPunct, "(") {
			continue
		}
		closeParams := matching(toks, i+2)
		if closeParams < 0 || closeParams+1 >= len(toks) || !toks[closeParams+1].Is(guard.ScriptPunct, "{") {
			continue
		}
		end := matching(toks, closeParams+1)
		if end < 0 {
			continue
		}
		p, c, invoked := -1, -1, []int(nil)
		param := ""
		if closeParams == i+4 && toks[i+3].Kind == guard.ScriptIdent {
			param = toks[i+3].Text
		}
		for j := closeParams + 2; j < end; j++ {
			switch {
			case toks[j].Is(guard.ScriptIdent, "preventDefault") && toks[j-1].Is(guard.ScriptPunct, "."):
				p = j
			case toks[j].Is(guard.ScriptIdent, "close") && toks[j-1].Is(guard.ScriptPunct, ".") &&
				dialog != "" && toks[j-2].Is(guard.ScriptIdent, dialog) && toks[j+1].Is(guard.ScriptPunct, "("):
				c = j
			case param != "" && toks[j].Is(guard.ScriptIdent, param) && !toks[j-1].Is(guard.ScriptPunct, ".") &&
				(toks[j+1].Is(guard.ScriptPunct, "(") ||
					(toks[j+1].Is(guard.ScriptPunct, ".") && toks[j+2].Kind == guard.ScriptIdent &&
						(toks[j+2].Text == "call" || toks[j+2].Text == "apply"))):
				invoked = append(invoked, j)
			}
		}
		if p >= 0 {
			answer, prevent, closes, calls = toks[i+1].Text, p, c, invoked
			break
		}
	}

	switch answer {
	case "":
		faults = append(faults, "no inner function of showModalDialog prevents the dialog form's default; "+
			"the form then closes the dialog after the callback, and any question the callback asked with it (#562)")
	default:
		if closes < 0 {
			faults = append(faults, answer+" never closes the dialog; it must close it before the callback runs (#562)")
		} else if closes < prevent {
			faults = append(faults, answer+" closes the dialog before preventing the form's default (#562)")
		}
		if len(calls) == 0 {
			faults = append(faults, answer+" never runs its callback, which it takes as its one parameter (#562)")
		}
		for _, at := range calls {
			if at < prevent || at < closes {
				faults = append(faults, answer+" runs its callback before it has prevented the form's default "+
					"and closed the dialog; a question the callback asks would be closed by the same click (#562)")
				break
			}
		}
	}

	for _, n := range []string{"1", "2"} {
		cb := callbacks[n]
		button := elementByID(toks, "_btnModal"+n)
		if button == "" {
			faults = append(faults, `showModalDialog holds no element got by id + "_btnModal`+n+`"`)
			continue
		}
		sets, argAt := 0, -1
		for j := 0; j+3 < len(toks); j++ {
			if !toks[j].Is(guard.ScriptIdent, button) || !toks[j+1].Is(guard.ScriptPunct, ".") ||
				!toks[j+2].Is(guard.ScriptIdent, "onclick") || !toks[j+3].Is(guard.ScriptPunct, "=") {
				continue
			}
			sets++
			if answer != "" && j+7 < len(toks) && toks[j+4].Is(guard.ScriptIdent, answer) &&
				toks[j+5].Is(guard.ScriptPunct, "(") && toks[j+6].Is(guard.ScriptIdent, cb) &&
				toks[j+7].Is(guard.ScriptPunct, ")") {
				argAt = j + 6
			}
		}
		if sets != 1 || argAt < 0 {
			faults = append(faults, button+".onclick is not set once, to the answer of "+cb+"; a click must "+
				"close the dialog before "+cb+" runs (#562)")
		}
		for j, tok := range toks {
			if tok.Is(guard.ScriptIdent, cb) && j != argAt {
				faults = append(faults, cb+" is read other than as the answer's argument; every call sets "+
					"both buttons, so a button given no callback just closes the dialog rather than keeping "+
					"a previous call's (#562)")
				break
			}
		}
	}
	return faults, true
}

// elementByID returns the variable toks assign `document.getElementById(<ident> + "<suffix>")` to,
// or "".
func elementByID(toks []guard.ScriptToken, suffix string) string {
	for k := 8; k+1 < len(toks); k++ {
		if toks[k].Is(guard.ScriptString, suffix) && toks[k+1].Is(guard.ScriptPunct, ")") &&
			toks[k-1].Is(guard.ScriptPunct, "+") && toks[k-2].Kind == guard.ScriptIdent &&
			toks[k-3].Is(guard.ScriptPunct, "(") && toks[k-4].Is(guard.ScriptIdent, "getElementById") &&
			toks[k-5].Is(guard.ScriptPunct, ".") && toks[k-6].Is(guard.ScriptIdent, "document") &&
			toks[k-7].Is(guard.ScriptPunct, "=") && toks[k-8].Kind == guard.ScriptIdent {
			return toks[k-8].Text
		}
	}
	return ""
}

// TestUtilsJS_DialogClosesBeforeItsAnswerRuns holds the real, embedded utils.js to the rule.
func TestUtilsJS_DialogClosesBeforeItsAnswerRuns(t *testing.T) {
	faults, ok := dialogAnswerFaults(utilsJS(t))
	require.True(t, ok, "static/utils.js: function showModalDialog not found, or its body cannot be read; "+
		"this check cannot read it (#562)")
	for _, f := range faults {
		t.Errorf("static/utils.js: %s", f)
	}
}

// dialogAnswerHead is what every fixture of showModalDialog below begins with.
const dialogAnswerHead = `function showModalDialog(id, title, message, btn1callback, btn2callback) {
  const dialog = document.getElementById(id + "_modalDialog");
  document.getElementById(id + "_modalDialogTitle").innerText = title;
`

// TestDialogAnswer_TheRule drives the finder over fixtures: the shape the rule wants passes, and
// each way of breaking it, the helper as it was before #562 among them, is reported.
func TestDialogAnswer_TheRule(t *testing.T) {
	const answer = `
  function answer(callback) {
    return function (event) {
      event.preventDefault();
      dialog.close();
      if (callback) {
        callback(event);
      }
    };
  }
`
	const buttons = `
  const btn1 = document.getElementById(id + "_btnModal1");
  if (btn1) {
    btn1.onclick = answer(btn1callback);
  }
  const btn2 = document.getElementById(id + "_btnModal2");
  if (btn2) {
    btn2.onclick = answer(btn2callback);
  }
  dialog.showModal();
}
`
	cases := []struct {
		name string
		src  string
		want []string
	}{
		{"the answer closes, then runs the callback, and both buttons are set", dialogAnswerHead + answer + buttons, nil},
		{"the answer runs the callback through call", dialogAnswerHead +
			strings.Replace(answer, "callback(event);", "callback.call(this, event);", 1) + buttons, nil},
		{"before #562: the callbacks are the handlers, set only when given", `function showModalDialog(id, title, message, btn1callback, btn2callback) {
  document.getElementById(id + "_modalDialogTitle").innerText = title;
  const btn1 = document.getElementById(id + "_btnModal1");
  if (btn1 && btn1callback) {
    btn1.onclick = null;
    btn1.onclick = btn1callback;
  }
  const btn2 = document.getElementById(id + "_btnModal2");
  if (btn2 && btn2callback) {
    btn2.onclick = null;
    btn2.onclick = btn2callback;
  }
  document.getElementById(id + "_modalDialog").showModal();
}
`, []string{
			`showModalDialog holds no element got by id + "_modalDialog"`,
			"no inner function of showModalDialog prevents the dialog form's default",
			"btn1.onclick is not set once",
			"btn1callback is read other than as the answer's argument",
			"btn2.onclick is not set once",
			"btn2callback is read other than as the answer's argument",
		}},
		{"the callback runs before the dialog closes", dialogAnswerHead + `
  function answer(callback) {
    return function (event) {
      event.preventDefault();
      if (callback) {
        callback(event);
      }
      dialog.close();
    };
  }
` + buttons, []string{"answer runs its callback before it has prevented the form's default and closed the dialog"}},
		{"the form's default is not prevented", dialogAnswerHead +
			strings.Replace(answer, "event.preventDefault();", "", 1) + buttons,
			[]string{"no inner function of showModalDialog prevents the dialog form's default",
				"btn1.onclick is not set once", "btn1callback is read other than as the answer's argument",
				"btn2.onclick is not set once", "btn2callback is read other than as the answer's argument"}},
		{"the dialog is never closed", dialogAnswerHead +
			strings.Replace(answer, "dialog.close();", "", 1) + buttons,
			[]string{"answer never closes the dialog"}},
		{"the callback is never run", dialogAnswerHead +
			strings.Replace(answer, "callback(event);", "", 1) + buttons,
			[]string{"answer never runs its callback"}},
		{"a button is set only when given a callback", dialogAnswerHead + answer +
			strings.Replace(buttons, "if (btn2) {", "if (btn2 && btn2callback) {", 1),
			[]string{"btn2callback is read other than as the answer's argument"}},
		{"a button is handed its callback bare", dialogAnswerHead + answer +
			strings.Replace(buttons, "answer(btn2callback)", "btn2callback", 1),
			[]string{"btn2.onclick is not set once", "btn2callback is read other than as the answer's argument"}},
		{"a button is handed the other button's callback", dialogAnswerHead + answer +
			strings.Replace(buttons, "answer(btn2callback)", "answer(btn1callback)", 1),
			[]string{"btn1callback is read other than as the answer's argument", "btn2.onclick is not set once"}},
		{"a button's onclick is set twice", dialogAnswerHead + answer +
			strings.Replace(buttons, "btn1.onclick = answer(btn1callback);", "btn1.onclick = null;\n    btn1.onclick = answer(btn1callback);", 1),
			[]string{"btn1.onclick is not set once"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			faults, ok := dialogAnswerFaults(tc.src)
			require.True(t, ok)
			require.Len(t, faults, len(tc.want), strings.Join(faults, "\n"))
			for i, w := range tc.want {
				assert.Contains(t, faults[i], w)
			}
		})
	}
}

// TestDialogAnswer_ASourceWithoutTheHelperIsNotRead pins the walk that reaches nothing: a source
// with no showModalDialog is reported as unreadable rather than as clean.
func TestDialogAnswer_ASourceWithoutTheHelperIsNotRead(t *testing.T) {
	_, ok := dialogAnswerFaults("function showDialog(id) {}\n")
	assert.False(t, ok)
}
