package web

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// passwordToggleRun is the program TestUtilsJS_PasswordToggles runs under Node. It draws a page in a
// small DOM of its own, as the templates draw it, loads the served utils.js into it, and wires the
// page as shell.js does (and, for the client secret, as the page's own script does). It then acts as
// a person does, a keyboard press, a pointer press, a submission, the browser bringing the page
// back, and writes down what the page then shows, which the test compares with what it must show.
//
// The DOM is the browser's, a boundary this module does not own, so it is stood in for: only what
// the scripts call, with one browser behaviour that matters here, an input's caret moving to its
// end when its type changes.
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
    this.checked = false;
    this.disabled = false;
    this.selectionStart = 0;
    this.selectionEnd = 0;
    this.selectionDirection = "none";
    const self = this;
    this.dataset = new Proxy({}, {
      get: function (_, p) { return typeof p === "string" && self.hasAttribute(dataAttr(p)) ? self.getAttribute(dataAttr(p)) : undefined; },
      set: function (_, p, v) { self.setAttribute(dataAttr(p), String(v)); return true; },
      has: function (_, p) { return self.hasAttribute(dataAttr(p)); },
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
}

class FakeDocument extends Target {
  constructor() {
    super();
    this.documentElement = new FakeElement(this, "html");
    this.documentElement.setAttribute("lang", "en");
    this.body = new FakeElement(this, "body");
    this.documentElement.append(this.body);
    this.activeElement = this.body;
  }
  createElement(tag) { return new FakeElement(this, tag); }
  getElementById(id) { let found = null; this.documentElement.walk(function (e) { if (!found && e.id === id) { found = e; } }); return found; }
  querySelectorAll(selector) {
    const m = /^([a-z]+)\[([a-z-]+)(?:=([A-Za-z]+))?\]$/.exec(selector);
    if (!m) { throw new Error("the fake DOM cannot select " + selector); }
    const found = [];
    this.documentElement.walk(function (e) {
      if (e.tagName === m[1].toUpperCase() && e.hasAttribute(m[2]) && (m[3] === undefined || e.getAttribute(m[2]) === m[3])) { found.push(e); }
    });
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

// page loads utils.js into a fresh window holding doc.
function page(doc, utils) {
  const window = new Target();
  const context = { document: doc, window: window, console: console };
  vm.createContext(context);
  vm.runInContext(utils, context, { filename: "utils.js" });
  const run = function (src) { return vm.runInContext(src, context); };
  // A utils.js without the behaviour wires nothing, so every step that expects it fails.
  return {
    window: window, context: context,
    setUp: run("typeof setUpPasswordToggles === 'function' ? setUpPasswordToggles : null") || function () {},
    toggle: run("typeof passwordToggle === 'function' ? passwordToggle : null") || function () { return { show: function () {} }; },
  };
}

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", function (chunk) { input += chunk; });
process.stdin.on("end", function () {
  const request = JSON.parse(input);
  const seen = {};
  // look writes down what a field's button, the field and its status region show.
  function look(step, field, button, row) {
    const status = row.nextElementSibling;
    seen[step + ": type"] = field.type;
    seen[step + ": button text"] = button.textContent;
    seen[step + ": button name"] = button.getAttribute("aria-label");
    seen[step + ": status"] = status && status.getAttribute("role") === "status" ? status.textContent : null;
  }

  // The change password page's new password, as the template draws it.
  {
    const doc = new FakeDocument();
    const field = el(doc, "input", { id: "newPassword", type: "password", name: "newPassword" });
    field.value = "correct horse";
    const button = el(doc, "button", {
      class: "button", type: "button", "data-password-toggle": "", "aria-controls": "newPassword",
      "aria-label": "Show new password", "data-hide-name": "Hide new password", "data-hide-label": "Hide",
      "data-shown-status": "Shown", "data-hidden-status": "Hidden", hidden: "",
    }, "Show");
    const row = el(doc, "div", { class: "input-row" }, "", [field, button]);
    const form = el(doc, "form", { method: "post" }, "", [el(doc, "div", { class: "field" }, "", [row])]);
    doc.body.append(form);
    const p = page(doc, request.utils);
    p.setUp();

    seen["drawn: button hidden"] = button.hidden;
    const status = row.nextElementSibling;
    seen["drawn: status role"] = status ? status.getAttribute("role") : null;
    seen["drawn: status class"] = status ? status.className : null;
    look("drawn", field, button, row);

    // A keyboard press: the focus is on the button, and stays there.
    button.focus();
    button.fire("click");
    look("pressed once", field, button, row);
    seen["pressed once: focus on the button"] = doc.activeElement === button;
    button.fire("click");
    look("pressed twice", field, button, row);

    // A pointer press while the person types in the field: the focus and the caret stay in it.
    field.focus();
    field.setSelectionRange(2, 5, "forward");
    seen["pointer press: mousedown default prevented"] = button.fire("mousedown").defaultPrevented;
    button.fire("click");
    look("pointer press", field, button, row);
    seen["pointer press: focus in the field"] = doc.activeElement === field;
    seen["pointer press: selection"] = field.selectionStart + "-" + field.selectionEnd + " " + field.selectionDirection;

    // Sending the form puts the field back to dots, a submission held back included.
    form.addEventListener("submit", function (event) { event.preventDefault(); });
    form.fire("submit");
    look("submitted", field, button, row);

    // The browser bringing the page back from its cache puts it back too.
    button.fire("click");
    p.window.fire("pageshow");
    look("brought back", field, button, row);

    // Wired twice, as by shell.js and a page's own script, a press still shows the field once.
    p.setUp();
    p.toggle(button);
    button.fire("click");
    look("wired twice", field, button, row);
    seen["wired twice: one controller"] = p.toggle(button) === p.toggle(button);
    p.toggle(button).show(false);
    look("shown false", field, button, row);
  }

  // The client secret's tab, as the new template draws it and as an operator's copy of the old one
  // does, with Generate answered at once by a new secret.
  for (const copy of ["new", "old"]) {
    const doc = new FakeDocument();
    const field = el(doc, "input", { id: "clientSecret", type: "password", name: "clientSecret", readonly: "" });
    field.value = "the-stored-secret";
    const attrs = copy === "new" ? {
      class: "button", type: "button", id: "showSecretBtn", "data-password-toggle": "", "aria-controls": "clientSecret",
      "aria-label": "Show client secret", "data-hide-name": "Hide client secret", "data-hide-label": "Hide",
      "data-shown-status": "Shown", "data-hidden-status": "Hidden", hidden: "",
    } : { class: "button", type: "button", id: "showSecretBtn", "aria-controls": "clientSecret", "data-hide-label": "Hide" };
    const button = el(doc, "button", attrs, "Show");
    const row = el(doc, "div", { class: "input-row" }, "", [field, button]);
    const generate = el(doc, "button", { class: "button", type: "button", id: "generateSecretBtn" }, "Generate a new secret");
    const panel = el(doc, "div", { class: "field", id: "confidentialClientPanel" }, "", [
      row, el(doc, "div", { class: "mt-2" }, "", [generate]),
      el(doc, "div", { id: "secret-status", role: "status", "data-generated": "New secret generated." }),
    ]);
    const confidential = el(doc, "input", { type: "radio", id: "confidentialClientRadio", name: "publicConfidential", value: "confidential" });
    confidential.checked = true;
    const form = el(doc, "form", { method: "post" }, "", [
      el(doc, "input", { type: "radio", id: "publicClientRadio", name: "publicConfidential", value: "public" }), confidential, panel,
    ]);
    doc.body.append(form);
    const p = page(doc, request.utils);
    p.context.sendAjaxRequest = function (props) { props.callback({ NewSecret: "a-new-secret" }); props.finished(); };
    p.context.showNotice = function (region, tone, text) { region.textContent = text; };
    p.setUp();
    vm.runInContext(request.page, p.context, { filename: "admin-clients-authentication.js" });
    const step = copy + " copy";

    seen[step + ", drawn: button hidden"] = button.hidden;
    button.fire("click");
    look(step + ", pressed once", field, button, row);
    button.fire("click");
    look(step + ", pressed twice", field, button, row);
    generate.fire("click");
    look(step + ", generated", field, button, row);
    seen[step + ", generated: value"] = field.value;
  }
  process.stdout.write(JSON.stringify(seen));
});
`

// What the page must show at each step, written as a person reads it: the field's type, the
// button's visible word and accessible name, and the status region's words (#722 decisions 7 and
// 8, and the assumed behaviour: reset on submit and pageshow, focus and caret kept, an old copy of
// the client secret's template still working).
var passwordToggleSeen = map[string]any{
	"drawn: button hidden": false,
	"drawn: status role":   "status",
	"drawn: status class":  "sr-only",
	"drawn: type":          "password",
	"drawn: button text":   "Show",
	"drawn: button name":   "Show new password",
	"drawn: status":        "",

	"pressed once: type":                "text",
	"pressed once: button text":         "Hide",
	"pressed once: button name":         "Hide new password",
	"pressed once: status":              "Shown",
	"pressed once: focus on the button": true,

	"pressed twice: type":        "password",
	"pressed twice: button text": "Show",
	"pressed twice: button name": "Show new password",
	"pressed twice: status":      "Hidden",

	"pointer press: mousedown default prevented": true,
	"pointer press: type":                        "text",
	"pointer press: button text":                 "Hide",
	"pointer press: button name":                 "Hide new password",
	"pointer press: status":                      "Shown",
	"pointer press: focus in the field":          true,
	"pointer press: selection":                   "2-5 forward",

	"submitted: type":        "password",
	"submitted: button text": "Show",
	"submitted: button name": "Show new password",
	"submitted: status":      "Hidden",

	"brought back: type":        "password",
	"brought back: button text": "Show",
	"brought back: button name": "Show new password",
	"brought back: status":      "Hidden",

	"wired twice: type":           "text",
	"wired twice: button text":    "Hide",
	"wired twice: button name":    "Hide new password",
	"wired twice: status":         "Shown",
	"wired twice: one controller": true,

	"shown false: type":        "password",
	"shown false: button text": "Show",
	"shown false: button name": "Show new password",
	"shown false: status":      "Hidden",

	"new copy, drawn: button hidden":       false,
	"new copy, pressed once: type":         "text",
	"new copy, pressed once: button text":  "Hide",
	"new copy, pressed once: button name":  "Hide client secret",
	"new copy, pressed once: status":       "Shown",
	"new copy, pressed twice: type":        "password",
	"new copy, pressed twice: button text": "Show",
	"new copy, pressed twice: button name": "Show client secret",
	"new copy, pressed twice: status":      "Hidden",
	"new copy, generated: type":            "text",
	"new copy, generated: button text":     "Hide",
	"new copy, generated: button name":     "Hide client secret",
	"new copy, generated: status":          "Shown",
	"new copy, generated: value":           "a-new-secret",

	// The old copy draws its button shown, with no name of its own and no status words, so it keeps
	// its text for a name and has no status region.
	"old copy, drawn: button hidden":       false,
	"old copy, pressed once: type":         "text",
	"old copy, pressed once: button text":  "Hide",
	"old copy, pressed once: button name":  nil,
	"old copy, pressed once: status":       nil,
	"old copy, pressed twice: type":        "password",
	"old copy, pressed twice: button text": "Show",
	"old copy, pressed twice: button name": nil,
	"old copy, pressed twice: status":      nil,
	"old copy, generated: type":            "text",
	"old copy, generated: button text":     "Hide",
	"old copy, generated: button name":     nil,
	"old copy, generated: status":          nil,
	"old copy, generated: value":           "a-new-secret",
}

// A password field's show/hide button, wired by utils.js, shows the password as text and back, its
// visible word, its name and the status region saying each state; keeps the focus where it was and
// the field's caret; puts the field back to dots when its form is sent and when the browser brings
// the page back; and works on the client secret, Generate included, in the template's new and old
// copies alike.
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
	pageScript, err := staticFS.ReadFile("static/pages/admin-clients-authentication.js")
	if err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(map[string]string{"utils": utilsJS(t), "page": string(pageScript)})
	if err != nil {
		t.Fatalf("encoding the scripts: %v", err)
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
