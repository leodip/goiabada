package web

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// passwordToggleRun is the program TestUtilsJS_PasswordToggles runs under Node. It draws a page in a
// small DOM of its own, as the sign-in and registration templates draw it, then loads the served
// utils.js into it, which wires the page when it loads, as a browser runs it with defer. It then
// acts as a person does, a keyboard press, a pointer press, a submission, the browser bringing the
// page back, and writes down what the page then shows, which the test compares with what it must
// show.
//
// The DOM is the browser's, a boundary this module does not own, so it is stood in for: only what
// utils.js calls, with one browser behaviour that matters here, an input's caret moving to its end
// when its type changes.
const passwordToggleRun = `"use strict";
const vm = require("vm");

function dataAttr(prop) { return "data-" + prop.replace(/[A-Z]/g, function (c) { return "-" + c.toLowerCase(); }); }

class FakeEvent {
  constructor(type) { this.type = type; this.defaultPrevented = false; this.target = null; this.persisted = true; }
  preventDefault() { this.defaultPrevented = true; }
}

class Target {
  constructor() { this.listeners = {}; }
  addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
  removeEventListener(type, fn) { this.listeners[type] = (this.listeners[type] || []).filter(function (f) { return f !== fn; }); }
  dispatchEvent(event) {
    if (!event.target) { event.target = this; }
    for (const fn of (this.listeners[event.type] || []).slice()) { fn.call(this, event); }
    return !event.defaultPrevented;
  }
  fire(type) { const event = new FakeEvent(type); this.dispatchEvent(event); return event; }
}

// matcher reads the selectors utils.js uses: a tag, with an attribute it must carry.
function matcher(selector) {
  const m = /^([a-z]+)(?:\[([a-z-]+)\])?$/.exec(selector);
  if (!m) { throw new Error("the fake DOM cannot select " + selector); }
  return function (e) { return e.tagName === m[1].toUpperCase() && (m[2] === undefined || e.hasAttribute(m[2])); };
}

class FakeElement extends Target {
  constructor(doc, tag) {
    super();
    this.ownerDocument = doc;
    this.tagName = tag.toUpperCase();
    this.attributes = new Map();
    this.children = [];
    this.parentElement = null;
    this.ownText = "";
    this.value = "";
    this.disabled = false;
    this.selectionStart = 0;
    this.selectionEnd = 0;
    this.selectionDirection = "none";
    const self = this;
    this.dataset = new Proxy({}, {
      get: function (_, p) { return typeof p === "string" && self.hasAttribute(dataAttr(p)) ? self.getAttribute(dataAttr(p)) : undefined; },
      set: function (_, p, v) { self.setAttribute(dataAttr(p), String(v)); return true; },
      has: function (_, p) { return self.hasAttribute(dataAttr(p)); },
      deleteProperty: function (_, p) { self.removeAttribute(dataAttr(p)); return true; },
    });
  }
  getAttribute(n) { return this.attributes.has(n) ? this.attributes.get(n) : null; }
  setAttribute(n, v) { this.attributes.set(n, String(v)); }
  hasAttribute(n) { return this.attributes.has(n); }
  removeAttribute(n) { this.attributes.delete(n); }
  get id() { return this.getAttribute("id") || ""; }
  get className() { return this.getAttribute("class") || ""; }
  set className(v) { this.setAttribute("class", v); }
  get hidden() { return this.hasAttribute("hidden"); }
  set hidden(v) { if (v) { this.setAttribute("hidden", ""); } else { this.removeAttribute("hidden"); } }
  get type() { return this.getAttribute("type") || ""; }
  set type(v) {
    this.setAttribute("type", v);
    if (this.tagName === "INPUT") {
      this.selectionStart = this.selectionEnd = this.value.length;
      this.selectionDirection = "none";
    }
  }
  get textContent() { return this.ownText + this.children.map(function (c) { return c.textContent; }).join(""); }
  set textContent(v) { this.ownText = String(v); this.children = []; }
  append() { for (const n of arguments) { n.parentElement = this; this.children.push(n); } }
  appendChild(n) { this.append(n); return n; }
  after() {
    const p = this.parentElement;
    let i = p.children.indexOf(this);
    for (const n of arguments) { n.parentElement = p; p.children.splice(++i, 0, n); }
  }
  get nextElementSibling() {
    const siblings = this.parentElement ? this.parentElement.children : [];
    return siblings[siblings.indexOf(this) + 1] || null;
  }
  get form() { let p = this.parentElement; while (p && p.tagName !== "FORM") { p = p.parentElement; } return p; }
  focus() { this.ownerDocument.activeElement = this; }
  setSelectionRange(start, end, direction) {
    this.selectionStart = start; this.selectionEnd = end; this.selectionDirection = direction || "none";
  }
  walk(visit) { visit(this); for (const c of this.children) { c.walk(visit); } }
  querySelectorAll(selector) {
    const match = matcher(selector);
    const found = [];
    for (const c of this.children) { c.walk(function (e) { if (match(e)) { found.push(e); } }); }
    return found;
  }
}

class FakeDocument extends Target {
  constructor() {
    super();
    this.documentElement = new FakeElement(this, "html");
    this.body = new FakeElement(this, "body");
    this.documentElement.append(this.body);
    this.activeElement = this.body;
  }
  createElement(tag) { return new FakeElement(this, tag); }
  getElementById(id) { let found = null; this.documentElement.walk(function (e) { if (!found && e.id === id) { found = e; } }); return found; }
  querySelectorAll(selector) {
    const match = matcher(selector);
    const found = [];
    this.documentElement.walk(function (e) { if (match(e)) { found.push(e); } });
    return found;
  }
}

// el builds an element: its tag, attributes, text and children.
function el(doc, tag, attrs, text, children) {
  const e = doc.createElement(tag);
  for (const name in attrs || {}) { e.setAttribute(name, attrs[name]); }
  if (text) { e.ownText = text; }
  e.append.apply(e, children || []);
  return e;
}

// field draws a password field in its input-row with its show/hide button, as the templates do.
function field(doc, id, show, hide) {
  const input = el(doc, "input", { class: "control", id: id, type: "password", name: id });
  const button = el(doc, "button", {
    class: "button", type: "button", "data-password-toggle": "", "aria-controls": id,
    "aria-label": show, "data-hide-name": hide, "data-hide-label": "Hide",
    "data-shown-status": "Shown", "data-hidden-status": "Hidden", hidden: "",
  }, "Show");
  const row = el(doc, "div", { class: "input-row" }, "", [input, button]);
  return { input: input, button: button, row: row, wrapper: el(doc, "div", { class: "field" }, "", [row]) };
}

// load runs utils.js in a fresh window holding doc, once the page is drawn, as defer runs it.
function load(doc, utils) {
  const window = new Target();
  const context = { document: doc, window: window, navigator: {}, history: { length: 1 }, console: console };
  vm.createContext(context);
  vm.runInContext(utils, context, { filename: "utils.js" });
  return window;
}

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", function (chunk) { input += chunk; });
process.stdin.on("end", function () {
  const request = JSON.parse(input);
  const seen = {};
  // look writes down what a field's button, the field and its status region show.
  function look(step, f) {
    const status = f.row.nextElementSibling;
    seen[step + ": type"] = f.input.type;
    seen[step + ": button text"] = f.button.textContent;
    seen[step + ": button name"] = f.button.getAttribute("aria-label");
    seen[step + ": status"] = status && status.getAttribute("role") === "status" ? status.textContent : null;
  }

  // The sign-in page's password, in its form that is sent once.
  {
    const doc = new FakeDocument();
    const password = field(doc, "password", "Show password", "Hide password");
    password.input.value = "correct horse";
    const form = el(doc, "form", { method: "post", "data-submit-once": "" }, "", [
      el(doc, "div", { class: "field" }, "", [el(doc, "input", { class: "control", id: "email", type: "email", name: "email" })]),
      password.wrapper,
      el(doc, "button", { class: "button button-primary", type: "submit" }, "Sign in"),
    ]);
    doc.body.append(form);
    const window = load(doc, request.utils);

    seen["drawn: button hidden"] = password.button.hidden;
    const status = password.row.nextElementSibling;
    seen["drawn: status role"] = status ? status.getAttribute("role") : null;
    seen["drawn: status class"] = status ? status.className : null;
    look("drawn", password);

    // A keyboard press: the focus is on the button, and stays there.
    password.button.focus();
    password.button.fire("click");
    look("pressed once", password);
    seen["pressed once: focus on the button"] = doc.activeElement === password.button;
    password.button.fire("click");
    look("pressed twice", password);

    // A pointer press while the person types in the field: the focus and the caret stay in it.
    password.input.focus();
    password.input.setSelectionRange(2, 5, "forward");
    seen["pointer press: mousedown default prevented"] = password.button.fire("mousedown").defaultPrevented;
    password.button.fire("click");
    look("pointer press", password);
    seen["pointer press: focus in the field"] = doc.activeElement === password.input;
    seen["pointer press: selection"] = password.input.selectionStart + "-" + password.input.selectionEnd + " " + password.input.selectionDirection;

    // Sending the form puts the field back to dots, and the submission goes.
    seen["submitted: sent"] = form.dispatchEvent(new FakeEvent("submit"));
    look("submitted", password);

    // The browser bringing the page back from its cache puts it back too.
    password.button.fire("click");
    look("shown again", password);
    window.fire("pageshow");
    look("brought back", password);
  }

  // The registration page's two fields: each button shows its own field.
  {
    const doc = new FakeDocument();
    const password = field(doc, "password", "Show password", "Hide password");
    const confirmation = field(doc, "passwordConfirmation", "Show password confirmation", "Hide password confirmation");
    const form = el(doc, "form", { method: "post" }, "", [password.wrapper, confirmation.wrapper]);
    doc.body.append(form);
    load(doc, request.utils);

    confirmation.button.fire("click");
    look("confirmation pressed, confirmation", confirmation);
    look("confirmation pressed, password", password);
    form.fire("submit");
    look("registration submitted, confirmation", confirmation);
  }
  process.stdout.write(JSON.stringify(seen));
});
`

// What the page must show at each step, written as a person reads it: the field's type, the
// button's visible word and accessible name, and the status region's words (#722 decisions 7 and
// 8, and the assumed behaviour: reset on submit and pageshow, focus and caret kept).
var passwordToggleSeen = map[string]any{
	"drawn: button hidden": false,
	"drawn: status role":   "status",
	"drawn: status class":  "sr-only",
	"drawn: type":          "password",
	"drawn: button text":   "Show",
	"drawn: button name":   "Show password",
	"drawn: status":        "",

	"pressed once: type":                "text",
	"pressed once: button text":         "Hide",
	"pressed once: button name":         "Hide password",
	"pressed once: status":              "Shown",
	"pressed once: focus on the button": true,

	"pressed twice: type":        "password",
	"pressed twice: button text": "Show",
	"pressed twice: button name": "Show password",
	"pressed twice: status":      "Hidden",

	"pointer press: mousedown default prevented": true,
	"pointer press: type":                        "text",
	"pointer press: button text":                 "Hide",
	"pointer press: button name":                 "Hide password",
	"pointer press: status":                      "Shown",
	"pointer press: focus in the field":          true,
	"pointer press: selection":                   "2-5 forward",

	"submitted: sent":        true,
	"submitted: type":        "password",
	"submitted: button text": "Show",
	"submitted: button name": "Show password",
	"submitted: status":      "Hidden",

	"shown again: type": "text",

	"brought back: type":        "password",
	"brought back: button text": "Show",
	"brought back: button name": "Show password",
	"brought back: status":      "Hidden",

	"confirmation pressed, confirmation: type":        "text",
	"confirmation pressed, confirmation: button text": "Hide",
	"confirmation pressed, confirmation: button name": "Hide password confirmation",
	"confirmation pressed, confirmation: status":      "Shown",
	"confirmation pressed, password: type":            "password",
	"confirmation pressed, password: button text":     "Show",
	"confirmation pressed, password: button name":     "Show password",
	"confirmation pressed, password: status":          "",

	"registration submitted, confirmation: type":        "password",
	"registration submitted, confirmation: button text": "Show",
	"registration submitted, confirmation: button name": "Show password confirmation",
	"registration submitted, confirmation: status":      "Hidden",
}

// A password field's show/hide button on the auth server's pages, wired by utils.js as it loads,
// shows the password as text and back, its visible word, its name and the status region saying
// each state; keeps the focus where it was and the field's caret; leaves the other field on the
// form alone; and puts the field back to dots when its form is sent, the sign-in's sent-once form
// included, and when the browser brings the page back.
func TestUtilsJS_PasswordToggles(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatalf("node is not on PATH: this test runs utils.js under Node, which the dev container and the " +
			"test jobs install at the version src/authserver/versions.yaml pins")
	}
	program := filepath.Join(t.TempDir(), "password-toggle.js")
	if writeErr := os.WriteFile(program, []byte(passwordToggleRun), 0o600); writeErr != nil {
		t.Fatalf("writing the program: %v", writeErr)
	}
	utils, err := fs.ReadFile(staticFS, "static/utils.js")
	if err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(map[string]string{"utils": string(utils)})
	if err != nil {
		t.Fatalf("encoding the script: %v", err)
	}

	cmd := exec.CommandContext(t.Context(), node, program)
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if runErr := cmd.Run(); runErr != nil {
		t.Fatalf("running utils.js under Node: %v: %s", runErr, strings.TrimSpace(stderr.String()))
	}
	var seen map[string]any
	if decodeErr := json.Unmarshal(stdout.Bytes(), &seen); decodeErr != nil {
		t.Fatalf("reading Node's answer: %v: %s", decodeErr, stdout.String())
	}
	steps := make([]string, 0, len(passwordToggleSeen))
	for step := range passwordToggleSeen {
		steps = append(steps, step)
	}
	sort.Strings(steps)
	for _, step := range steps {
		want := passwordToggleSeen[step]
		got, ok := seen[step]
		if !ok {
			t.Errorf("%s: not seen", step)
			continue
		}
		if got != want {
			t.Errorf("%s: got %#v, want %#v", step, got, want)
		}
	}
}
