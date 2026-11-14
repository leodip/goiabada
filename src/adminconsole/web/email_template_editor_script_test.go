package web

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// editorRun is the program the email template editor's tests run under Node: it loads the served
// page script against a stand-in of the editor (#818 decision 14), the three fields, the
// placeholder buttons, the language links, the Reset form and the data block holding the text as
// saved, then plays the steps it is handed and answers what each look saw.
const editorRun = `"use strict";
const vm = require("vm");
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", function (chunk) { input += chunk; });
process.stdin.on("end", function () {
  const request = JSON.parse(input);

  function listeners() {
    const map = {};
    return {
      add: function (type, fn) { (map[type] = map[type] || []).push(fn); },
      fire: function (type, event) { (map[type] || []).forEach(function (fn) { fn(event); }); },
    };
  }
  function makeEvent(type, target, extra) {
    const event = Object.assign({ type: type, target: target, defaultPrevented: false, returnValue: undefined,
      preventDefault: function () { event.defaultPrevented = true; } }, extra || {});
    return event;
  }
  function element(props) {
    const own = listeners();
    const el = Object.assign({ dataset: {}, hidden: false, value: "", selectionStart: 0, selectionEnd: 0,
      addEventListener: own.add, fire: own.fire,
      dispatchEvent: function (event) { own.fire(event.type, event); if (event.bubbles) { documentListeners.fire(event.type, event); } return true; },
      closest: function () { return null; },
      focus: function () { focused = el; own.fire("focus", makeEvent("focus", el)); },
      setSelectionRange: function (start, end) { el.selectionStart = start; el.selectionEnd = end; },
      getAttribute: function (name) { return el.attributes ? el.attributes[name] : null; } }, props);
    return el;
  }

  const documentListeners = listeners();
  const windowListeners = listeners();
  let focused = null;
  let dialog = null;
  let navigatedTo = null;

  const subject = element({ id: "subject", value: request.saved.subject });
  const body = element({ id: "body", value: request.saved.body });
  const fields = [subject, body];
  let buttonLabel = null;
  if (request.saved.buttonLabel !== undefined) {
    buttonLabel = element({ id: "buttonLabel", value: request.saved.buttonLabel });
    fields.push(buttonLabel);
  }
  const form = element({ id: "emailTemplateForm" });
  form.querySelectorAll = function () { return []; };
  const resetForm = element({ id: "resetForm" });
  const placeholders = request.placeholders.map(function (p) {
    return element({ dataset: { placeholder: p.name, inSubject: String(p.inSubject) } });
  });
  const languages = element({ id: "emailTemplateLanguages",
    dataset: { discardDialog: "discardChanges", discardTitle: "Discard your changes?", discardBody: "The changes are not saved." } });
  const links = request.languages.map(function (tag) {
    return element({ attributes: { href: "/admin/settings/email/templates/welcome/" + tag }, href: "https://console.example/admin/settings/email/templates/welcome/" + tag });
  });
  links.forEach(function (link) { link.closest = function (selector) { return selector === "a" || selector === "a[href]" ? link : null; }; });
  languages.querySelectorAll = function () { return links; };
  const savedBlock = { textContent: JSON.stringify(request.saved) };
  const byId = { subject: subject, body: body, buttonLabel: buttonLabel, emailTemplateForm: form, emailTemplateLanguages: languages,
    emailTemplateSaved: savedBlock };

  const context = {
    JSON: JSON,
    Event: function (type, init) { return makeEvent(type, null, { bubbles: !!(init && init.bubbles) }); },
    document: {
      getElementById: function (id) { return byId[id] || null; },
      querySelectorAll: function (selector) { return selector.indexOf("data-placeholder") >= 0 ? placeholders : []; },
      addEventListener: documentListeners.add,
      get activeElement() { return focused; },
    },
    window: { addEventListener: windowListeners.add, location: { assign: function (url) { navigatedTo = url; } } },
    showModalDialog: function (id, title, message, cancel, confirm) {
      dialog = { id: id, title: title, message: message, confirm: confirm };
    },
  };
  context.location = context.window.location;
  vm.createContext(context);
  vm.runInContext(request.script, context, { filename: "email-template-editor.js" });

  function field(id) { return byId[id]; }
  function unload() {
    const event = makeEvent("beforeunload", context.window);
    windowListeners.fire("beforeunload", event);
    return event.defaultPrevented || (event.returnValue !== undefined && event.returnValue !== null);
  }
  function submit(target) {
    const event = makeEvent("submit", target, { bubbles: true });
    target.fire("submit", event);
    documentListeners.fire("submit", event);
  }

  const looks = [];
  request.steps.forEach(function (step) {
    switch (step.do) {
      case "type":
        field(step.id).value = step.value;
        field(step.id).dispatchEvent(makeEvent("input", field(step.id), { bubbles: true }));
        break;
      case "caret":
        field(step.id).focus();
        field(step.id).setSelectionRange(step.start, step.end === undefined ? step.start : step.end);
        documentListeners.fire("focusin", makeEvent("focusin", field(step.id)));
        break;
      case "insert":
        placeholders.filter(function (p) { return p.dataset.placeholder === step.name; })[0]
          .fire("click", makeEvent("click", null));
        break;
      case "language": {
        const link = links[request.languages.indexOf(step.tag)];
        const event = makeEvent("click", link, { button: 0 });
        languages.fire("click", event);
        if (!event.defaultPrevented) { navigatedTo = link.attributes.href; }
        break;
      }
      case "discard":
        dialog.confirm(makeEvent("click", null));
        dialog = null;
        break;
      case "keep":
        dialog = null;
        break;
      case "save":
        submit(form);
        break;
      case "resetBeingAsked": {
        // The Reset form's own handler asks first and keeps the submission from going.
        const event = makeEvent("submit", resetForm, { bubbles: true });
        event.preventDefault();
        documentListeners.fire("submit", event);
        break;
      }
      case "resetConfirmed":
        submit(resetForm);
        break;
      case "pageshow":
        windowListeners.fire("pageshow", makeEvent("pageshow", context.window));
        break;
      case "lookAtEditor":
        looks.push({ subject: subject.value, buttonLabel: buttonLabel ? buttonLabel.value : null, body: body.value,
          focused: focused ? focused.id : null, caret: focused ? focused.selectionStart : null,
          leavingAsks: unload(), dialog: dialog ? { id: dialog.id, title: dialog.title, message: dialog.message } : null,
          navigatedTo: navigatedTo });
        navigatedTo = null;
        break;
      default:
        throw new Error("unknown step " + step.do);
    }
  });
  process.stdout.write(JSON.stringify(looks));
});
`

type editorStep struct {
	Do    string `json:"do"`
	ID    string `json:"id,omitempty"`
	Value string `json:"value,omitempty"`
	Name  string `json:"name,omitempty"`
	Tag   string `json:"tag,omitempty"`
	Start *int   `json:"start,omitempty"`
	End   *int   `json:"end,omitempty"`
}

type editorDialog struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Message string `json:"message"`
}

type editorLook struct {
	Subject     string        `json:"subject"`
	ButtonLabel *string       `json:"buttonLabel"`
	Body        string        `json:"body"`
	Focused     *string       `json:"focused"`
	Caret       *int          `json:"caret"`
	LeavingAsks bool          `json:"leavingAsks"`
	Dialog      *editorDialog `json:"dialog"`
	NavigatedTo *string       `json:"navigatedTo"`
}

type editorPlaceholder struct {
	Name      string `json:"name"`
	InSubject bool   `json:"inSubject"`
}

type editorText struct {
	Subject     string  `json:"subject"`
	ButtonLabel *string `json:"buttonLabel,omitempty"`
	Body        string  `json:"body"`
}

func typeInEditor(id, value string) editorStep { return editorStep{Do: "type", ID: id, Value: value} }
func caretInEditor(id string, at int) editorStep {
	return editorStep{Do: "caret", ID: id, Start: &at}
}
func selectInEditor(id string, start, end int) editorStep {
	return editorStep{Do: "caret", ID: id, Start: &start, End: &end}
}
func insertPlaceholder(name string) editorStep   { return editorStep{Do: "insert", Name: name} }
func chooseEditorLanguage(tag string) editorStep { return editorStep{Do: "language", Tag: tag} }

var (
	lookAtEditor    = editorStep{Do: "lookAtEditor"}
	discardChanges  = editorStep{Do: "discard"}
	keepChanges     = editorStep{Do: "keep"}
	saveForm        = editorStep{Do: "save"}
	resetBeingAsked = editorStep{Do: "resetBeingAsked"}
	resetConfirmed  = editorStep{Do: "resetConfirmed"}
	showPageAgain   = editorStep{Do: "pageshow"}
)

// welcomeText is the welcome email's text as saved.
func welcomeText() editorText {
	label := "Sign in"
	return editorText{Subject: "Welcome!", ButtonLabel: &label, Body: "Hello,\n\n{{button}}\n\nThanks"}
}

var welcomePlaceholders = []editorPlaceholder{{Name: "app_name", InSubject: true}, {Name: "link"}, {Name: "button"}}

func runEditor(t *testing.T, saved editorText, steps ...editorStep) []editorLook {
	t.Helper()
	node, err := exec.LookPath("node")
	require.NoError(t, err, "node is not on PATH: this test runs a page script under Node, which the dev container and "+
		"the test jobs install at the version src/authserver/versions.yaml pins")
	script, err := fs.ReadFile(StaticFS(), "pages/email-template-editor.js")
	require.NoError(t, err, "reading the served script")
	program := filepath.Join(t.TempDir(), "editor.js")
	require.NoError(t, os.WriteFile(program, []byte(editorRun), 0o600))
	input, err := json.Marshal(map[string]any{
		"script": string(script), "saved": saved, "placeholders": welcomePlaceholders,
		"languages": []string{"en", "de", "fr"}, "steps": steps,
	})
	require.NoError(t, err)

	cmd := exec.CommandContext(t.Context(), node, program)
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	require.NoError(t, cmd.Run(), "running the script under Node: %s", strings.TrimSpace(stderr.String()))
	var looks []editorLook
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &looks), "reading Node's answer: %s", stdout.String())
	return looks
}

func strOf(s string) *string { return &s }

// A placeholder button inserts {{name}} at the cursor of the field last focused, replacing what is
// selected and leaving the cursor after it. One the subject does not take, the link or the button,
// goes into the body whichever field was focused, and the button goes on a line of its own.
func TestEmailTemplateEditorJS_APlaceholderButtonInsertsAtTheCursor(t *testing.T) {
	looks := runEditor(t, welcomeText(),
		caretInEditor("body", 6), insertPlaceholder("app_name"), lookAtEditor,
		caretInEditor("subject", 7), insertPlaceholder("app_name"), lookAtEditor,
		selectInEditor("subject", 0, 7), insertPlaceholder("app_name"), lookAtEditor,
		caretInEditor("subject", 3), insertPlaceholder("link"), lookAtEditor,
		caretInEditor("body", 0), insertPlaceholder("button"), lookAtEditor,
	)
	require.Len(t, looks, 5)

	assert.Equal(t, "Hello,{{app_name}}\n\n{{button}}\n\nThanks", looks[0].Body)
	assert.Equal(t, strOf("body"), looks[0].Focused)
	assert.Equal(t, 6+len("{{app_name}}"), *looks[0].Caret)

	assert.Equal(t, "Welcome{{app_name}}!", looks[1].Subject, "a text placeholder goes into the subject when it was focused")
	assert.Equal(t, strOf("subject"), looks[1].Focused)
	assert.Equal(t, "{{app_name}}{{app_name}}!", looks[2].Subject, "the selection is replaced")

	assert.Equal(t, "{{app_name}}{{app_name}}!", looks[3].Subject, "the subject never takes the link")
	assert.Equal(t, "Hello,{{app_name}}{{link}}\n\n{{button}}\n\nThanks", looks[3].Body,
		"the link goes into the body, where its cursor was left")
	assert.Equal(t, strOf("body"), looks[3].Focused)

	assert.Equal(t, "{{button}}\nHello,{{app_name}}{{link}}\n\n{{button}}\n\nThanks", looks[4].Body,
		"the button goes on a line of its own")
}

// The button inserted in the middle of a line breaks the line on both sides of it, and inserted
// where a line already ends or starts adds no blank line.
func TestEmailTemplateEditorJS_TheButtonIsAloneOnItsLine(t *testing.T) {
	looks := runEditor(t, welcomeText(),
		caretInEditor("body", 3), insertPlaceholder("button"), lookAtEditor,
	)
	assert.Equal(t, "Hel\n{{button}}\nlo,\n\n{{button}}\n\nThanks", looks[0].Body)

	looks = runEditor(t, welcomeText(), caretInEditor("body", 7), insertPlaceholder("button"), lookAtEditor)
	assert.Equal(t, "Hello,\n{{button}}\n{{button}}\n\nThanks", looks[0].Body)
}

// Leaving the page asks first only while the form holds text that is not saved: typing a change,
// a placeholder inserted, a change typed back to the saved text. Saving and a confirmed Reset leave
// without asking; a Reset whose question is still open does not, and showing the page again from
// the cache, as on Back, arms the question again.
func TestEmailTemplateEditorJS_LeavingWithUnsavedChangesAsksFirst(t *testing.T) {
	looks := runEditor(t, welcomeText(),
		lookAtEditor,
		typeInEditor("subject", "Welcome aboard!"), lookAtEditor,
		typeInEditor("subject", "Welcome!"), lookAtEditor,
		typeInEditor("buttonLabel", "Go"), lookAtEditor,
		typeInEditor("buttonLabel", "Sign in"), caretInEditor("body", 0), insertPlaceholder("app_name"), lookAtEditor,
		resetBeingAsked, lookAtEditor,
		saveForm, lookAtEditor,
		showPageAgain, lookAtEditor,
		resetConfirmed, lookAtEditor,
	)
	require.Len(t, looks, 9)
	assert.False(t, looks[0].LeavingAsks, "nothing changed")
	assert.True(t, looks[1].LeavingAsks, "the subject changed")
	assert.False(t, looks[2].LeavingAsks, "the subject typed back to the saved text")
	assert.True(t, looks[3].LeavingAsks, "the button label changed")
	assert.True(t, looks[4].LeavingAsks, "a placeholder inserted")
	assert.True(t, looks[5].LeavingAsks, "a Reset still being asked about has not left")
	assert.False(t, looks[6].LeavingAsks, "a saveForm sends the changes")
	assert.True(t, looks[7].LeavingAsks, "the page shown again asks again")
	assert.False(t, looks[8].LeavingAsks, "a Reset once confirmed discards the changes")
}

// The body is compared as the form sends it: a line break typed as CRLF is the saved LF.
func TestEmailTemplateEditorJS_LineBreaksAreNotAChange(t *testing.T) {
	looks := runEditor(t, welcomeText(), typeInEditor("body", "Hello,\r\n\r\n{{button}}\r\n\r\nThanks"), lookAtEditor)
	assert.False(t, looks[0].LeavingAsks)
}

// Choosing another language with unsaved changes asks first in the page's dialog, and goes only on
// Discard; with nothing changed it goes at once.
func TestEmailTemplateEditorJS_ChoosingALanguageWithUnsavedChangesAsksFirst(t *testing.T) {
	looks := runEditor(t, welcomeText(),
		chooseEditorLanguage("de"), lookAtEditor,
		typeInEditor("body", "Hi"), chooseEditorLanguage("fr"), lookAtEditor,
		keepChanges, lookAtEditor,
		chooseEditorLanguage("fr"), discardChanges, lookAtEditor,
	)
	require.Len(t, looks, 4)

	assert.Nil(t, looks[0].Dialog)
	assert.Equal(t, strOf("/admin/settings/email/templates/welcome/de"), looks[0].NavigatedTo, "nothing to lose: it goes")

	require.NotNil(t, looks[1].Dialog, "unsaved changes: it asks")
	assert.Equal(t, editorDialog{ID: "discardChanges", Title: "Discard your changes?", Message: "The changes are not saved."}, *looks[1].Dialog)
	assert.Nil(t, looks[1].NavigatedTo, "and does not go")

	assert.Nil(t, looks[2].NavigatedTo, "Cancel stays")
	assert.Equal(t, "Hi", looks[2].Body)

	assert.Equal(t, strOf("https://console.example/admin/settings/email/templates/welcome/fr"), looks[3].NavigatedTo, "Discard goes")
	assert.False(t, looks[3].LeavingAsks, "and the browser does not ask a second time")
}

// An email with no button has no label field, and its changes are the subject's and the body's.
func TestEmailTemplateEditorJS_AnEmailWithoutAButton(t *testing.T) {
	saved := editorText{Subject: "Bye", Body: "Hello {{name}}"}
	looks := runEditor(t, saved, lookAtEditor, typeInEditor("body", "Bye {{name}}"), lookAtEditor)
	assert.False(t, looks[0].LeavingAsks)
	assert.Nil(t, looks[0].ButtonLabel)
	assert.True(t, looks[1].LeavingAsks)
}
