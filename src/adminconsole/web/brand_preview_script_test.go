package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// brandPreviewRun is the program the TestBrandPreviewJS tests run under Node (#811). It draws the
// brand editor in a small DOM of its own, as admin_settings_branding_brand.html and the
// brand_sample partial draw it: the form's Appearance and theme cards, each with its swatch, the
// preview's sentences on the appearance and its Light/Dark switch outside the form, drawn for the
// appearance the form was drawn with, the two samples, light and dark, hidden until styled, and the
// palettes data block. The swatches start in a color no theme has, so a swatch the script does not
// draw keeps it. It
// loads the served brand-preview.js into it, then acts as a person and a browser do: picking a
// theme or a mode (a radio checked, then its input and change events, which bubble), a browser
// restoring the form with no event, and pageshow. At each "look" it writes down what each sample
// shows, every style property any element carries, which of the switch and the sentences show,
// and the colors each card's swatch is drawn in, token by token.
//
// The DOM is the browser's, a boundary this module does not own, so it is stood in for: only what
// a page script reads, with radios unchecking the rest of their group, as a browser's do. A
// selector it cannot read fails the run rather than matching nothing.
const brandPreviewRun = `"use strict";
const vm = require("vm");

// The color the page's swatches start in, which no palette holds.
const staleColor = "#5e7a1e";

function dataAttr(prop) { return "data-" + prop.replace(/[A-Z]/g, function (c) { return "-" + c.toLowerCase(); }); }

function compileCompound(text) {
  const tests = [];
  let rest = text;
  const tag = /^[a-zA-Z][\w-]*/.exec(rest);
  if (tag) {
    const name = tag[0].toUpperCase();
    tests.push(function (el) { return el.tagName === name; });
    rest = rest.slice(tag[0].length);
  }
  while (rest) {
    let m;
    if ((m = /^#([\w-]+)/.exec(rest))) {
      const id = m[1];
      tests.push(function (el) { return el.getAttribute("id") === id; });
    } else if ((m = /^\.([\w-]+)/.exec(rest))) {
      const c = m[1];
      tests.push(function (el) { return (el.getAttribute("class") || "").split(/\s+/).indexOf(c) >= 0; });
    } else if ((m = /^\[([\w-]+)(?:=(?:"([^"]*)"|'([^']*)'))?\]/.exec(rest))) {
      const n = m[1];
      const v = m[2] !== undefined ? m[2] : m[3];
      tests.push(v === undefined
        ? function (el) { return el.hasAttribute(n); }
        : function (el) { return el.getAttribute(n) === v; });
    } else if ((m = /^:checked/.exec(rest))) {
      tests.push(function (el) { return el.checked === true; });
    } else {
      throw new Error("the stand-in document cannot read the selector " + JSON.stringify(text));
    }
    rest = rest.slice(m[0].length);
  }
  return function (el) { return tests.every(function (t) { return t(el); }); };
}

function compile(selector) {
  const alternatives = selector.split(",").map(function (s) { return s.trim().split(/\s+/).map(compileCompound); });
  return function (el) {
    return alternatives.some(function (chain) {
      if (!chain[chain.length - 1](el)) { return false; }
      let i = chain.length - 2;
      for (let a = el.parentNode; i >= 0 && a && a.isElement; a = a.parentNode) {
        if (chain[i](a)) { i--; }
      }
      return i < 0;
    });
  };
}

function makeStyle() {
  const props = {};
  const api = {
    setProperty: function (n, v) { props[n] = String(v); },
    getPropertyValue: function (n) { return props[n] || ""; },
    removeProperty: function (n) { const v = props[n] || ""; delete props[n]; return v; },
  };
  const style = new Proxy(api, {
    get: function (t, p) { return p in t ? t[p] : (props[p] || ""); },
    set: function (t, p, v) { props[String(p)] = String(v); return true; },
  });
  return { style: style, props: props };
}

class Node {
  constructor() { this.listeners = {}; this.parentNode = null; this.children = []; }
  addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
  removeEventListener(type, fn) { this.listeners[type] = (this.listeners[type] || []).filter(function (f) { return f !== fn; }); }
  descendants() {
    const out = [];
    const walk = function (n) { for (const c of n.children) { out.push(c); walk(c); } };
    walk(this);
    return out;
  }
  querySelectorAll(selector) { return this.descendants().filter(compile(selector)); }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  appendChild(child) { child.parentNode = this; this.children.push(child); return child; }
}

class Element extends Node {
  constructor(doc, tag, attrs) {
    super();
    this.isElement = true;
    this.ownerDocument = doc;
    this.tagName = tag.toUpperCase();
    this.attributes = new Map(Object.entries(attrs || {}));
    this.ownText = "";
    const s = makeStyle();
    this.style = s.style;
    this.styleProps = s.props;
    this.checked = this.attributes.has("checked");
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
  toggleAttribute(n, force) {
    const on = force === undefined ? !this.hasAttribute(n) : !!force;
    if (on) { this.setAttribute(n, ""); } else { this.removeAttribute(n); }
    return on;
  }
  get id() { return this.getAttribute("id") || ""; }
  get name() { return this.getAttribute("name") || ""; }
  get type() { return this.getAttribute("type") || ""; }
  get value() { return this.getAttribute("value") || ""; }
  get hidden() { return this.hasAttribute("hidden"); }
  set hidden(v) { this.toggleAttribute("hidden", !!v); }
  get textContent() { return this.ownText + this.children.map(function (c) { return c.textContent; }).join(""); }
  set textContent(v) { this.children = []; this.ownText = String(v); }
  get checked() { return this._checked; }
  set checked(v) {
    this._checked = !!v;
    if (this._checked && this.type === "radio" && this.ownerDocument.documentElement) {
      for (const other of this.ownerDocument.querySelectorAll("input")) {
        if (other !== this && other.type === "radio" && other.name === this.name) { other._checked = false; }
      }
    }
  }
  matches(selector) { return compile(selector)(this); }
  closest(selector) {
    const test = compile(selector);
    for (let n = this; n && n.isElement; n = n.parentNode) { if (test(n)) { return n; } }
    return null;
  }
  get describe() {
    return this.tagName.toLowerCase() + (this.id ? "#" + this.id : "") +
      (this.hasAttribute("data-brand-sample") ? "[data-brand-sample=" + this.getAttribute("data-brand-sample") + "]" : "");
  }
}

class Document extends Node {
  constructor() { super(); this.readyState = "interactive"; this.documentElement = null; }
  get body() { return this.documentElement.children[1]; }
  getElementById(id) { return this.querySelector("#" + id); }
  createElement(tag) { return new Element(this, tag); }
}

class Window extends Node {}

function event(type, bubbles, extra) {
  const e = Object.assign({ type: type, bubbles: bubbles, defaultPrevented: false, stopped: false, target: null, currentTarget: null }, extra || {});
  e.preventDefault = function () { e.defaultPrevented = true; };
  e.stopPropagation = function () { e.stopped = true; };
  return e;
}

function dispatch(target, e, doc, win) {
  e.target = target;
  const path = [target];
  if (e.bubbles) {
    for (let n = target.parentNode; n; n = n.parentNode) { path.push(n); }
    if (path[path.length - 1] === doc) { path.push(win); }
  }
  for (const n of path) {
    e.currentTarget = n;
    for (const fn of (n.listeners[e.type] || []).slice()) { fn.call(n, e); }
    if (e.stopped) { break; }
  }
}

function build(request) {
  const doc = new Document();
  const win = new Window();
  const el = function (tag, attrs, children) {
    const e = new Element(doc, tag, attrs);
    for (const c of children || []) { e.appendChild(c); }
    return e;
  };
  const radio = function (name, value, checked) {
    const attrs = { type: "radio", id: name + "-" + value, name: name, value: value };
    if (checked) { attrs.checked = ""; }
    return el("input", attrs);
  };
  const sample = function (mode) {
    return el("div", { class: "brand-sample", "data-brand-sample": mode, hidden: "", inert: "", "aria-hidden": "true" }, [
      el("div", { class: "panel auth-card" }, [el("div", { class: "panel-body" }, [
        el("p", { class: "auth-brand" }), el("p", { class: "auth-title" }), el("p", { class: "auth-lead" }),
        el("div", { class: "stacked" }, [
          el("div", { class: "notice notice-danger" }),
          el("div", { class: "field" }, [el("span", { class: "control" })]),
          el("div", { class: "field" }, [el("span", { class: "control", "aria-invalid": "true" })]),
          el("div", { class: "auth-actions" }, [el("span", { class: "button" }), el("span", { class: "button button-primary" })]),
        ]),
      ])]),
    ]);
  };
  // A swatch as the brand_swatch partial draws it, one SVG per mode, in the stale color: each
  // shape names the token its fill, or its border, is drawn from.
  const swatch = function (attrs, modes) {
    return el("span", Object.assign({ class: "theme-swatch", "aria-hidden": "true" }, attrs), modes.map(function () {
      return el("svg", { viewBox: "0 0 120 64" }, [
        el("rect", { fill: staleColor, "data-fill": "canvas" }),
        el("rect", { fill: staleColor, stroke: staleColor, "data-fill": "surface", "data-stroke": "line" }),
        el("rect", { fill: staleColor, "data-fill": "ink" }),
        el("rect", { fill: staleColor, "data-fill": "ink-muted" }),
        el("rect", { fill: staleColor, "data-fill": "brand" }),
      ]);
    }));
  };
  const appearanceCard = function (value, modes) {
    return el("label", { class: "option-card" }, [
      radio("appearance", value, request.appearance === value),
      el("span", {}, [swatch({ "data-appearance-swatch": modes.join(" ") }, modes)]),
    ]);
  };
  const themeCard = function (key) {
    return el("label", { class: "option-card" }, [
      radio("theme", key, key === request.theme),
      el("span", {}, [swatch({}, ["light", "dark"])]),
    ]);
  };
  // The appearance the page was drawn with, as the template reads it: Light or Dark, else
  // Automatic.
  const drawnAppearance = request.appearance === "light" || request.appearance === "dark" ? request.appearance : "auto";
  const note = function (appearance) {
    const attrs = { "data-brand-preview-note": appearance };
    if (appearance !== drawnAppearance) { attrs.hidden = ""; }
    return el("span", attrs);
  };
  const switchAttrs = { class: "brand-preview-switch" };
  if (drawnAppearance !== "auto") { switchAttrs.hidden = ""; }
  const palettes = el("script", { type: "application/json", id: "brand-palettes" });
  palettes.textContent = JSON.stringify(request.palettes);
  const html = el("html", { lang: "en" }, [
    el("head"),
    el("body", {}, [el("main", { id: "main" }, [
      el("div", { class: "brand-editor" }, [
        el("form", { class: "panel", method: "post" }, [
          el("input", { class: "control", id: "name", type: "text", name: "name", value: "Autumn" }),
          el("fieldset", {}, [
            appearanceCard("auto", ["light", "dark"]),
            appearanceCard("light", ["light"]),
            appearanceCard("dark", ["dark"]),
          ]),
          el("fieldset", {}, request.themeCards.map(themeCard)),
        ]),
        el("section", { class: "brand-preview" }, [
          el("div", { class: "brand-preview-header" }, [
            el("h2", { class: "brand-preview-title" }),
            el("fieldset", switchAttrs, [
              radio("brandPreviewMode", "light", true),
              radio("brandPreviewMode", "dark", false),
            ]),
          ]),
          el("p", { class: "field-hint" }, [
            el("span"),
            note("auto"),
            note("light"),
            note("dark"),
          ]),
          sample("light"),
          sample("dark"),
        ]),
      ]),
      palettes,
    ])]),
  ]);
  doc.appendChild(html);
  doc.documentElement = html;
  return { doc: doc, win: win };
}

// swatchColors answers, for each SVG of a swatch, the color each token is drawn in.
function swatchColors(span) {
  return span.querySelectorAll("svg").map(function (svg) {
    const colors = {};
    for (const shape of svg.querySelectorAll("rect")) {
      if (shape.hasAttribute("data-fill")) { colors[shape.getAttribute("data-fill")] = shape.getAttribute("fill"); }
      if (shape.hasAttribute("data-stroke")) { colors[shape.getAttribute("data-stroke")] = shape.getAttribute("stroke"); }
    }
    return colors;
  });
}

function look(doc) {
  const swatches = { appearance: {}, theme: {} };
  for (const card of doc.querySelectorAll("label.option-card")) {
    const choice = card.querySelector("input");
    swatches[choice.name][choice.value] = swatchColors(card.querySelector(".theme-swatch"));
  }
  const notes = {};
  for (const n of doc.querySelectorAll("[data-brand-preview-note]")) {
    notes[n.getAttribute("data-brand-preview-note")] = n.hidden;
  }
  const samples = {};
  for (const s of doc.querySelectorAll("[data-brand-sample]")) {
    samples[s.getAttribute("data-brand-sample")] = { hidden: s.hidden, style: Object.assign({}, s.styleProps) };
  }
  const styledElsewhere = [];
  for (const n of [doc.documentElement].concat(doc.documentElement.descendants())) {
    if (!n.hasAttribute("data-brand-sample") && Object.keys(n.styleProps).length > 0) {
      styledElsewhere.push(n.describe + " " + JSON.stringify(n.styleProps));
    }
  }
  return {
    samples: samples,
    styledElsewhere: styledElsewhere,
    switchHidden: doc.querySelector(".brand-preview-switch").hidden,
    notesHidden: notes,
    swatches: swatches,
  };
}

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", function (chunk) { input += chunk; });
process.stdin.on("end", function () {
  const request = JSON.parse(input);
  const page = build(request);
  const doc = page.doc;
  const win = page.win;
  const looks = [];
  const context = { document: doc, window: win, console: console, JSON: JSON, Object: Object };
  win.document = doc;
  vm.createContext(context);
  for (const step of request.steps) {
    if (step.do === "load") {
      vm.runInContext(request.script, context, { filename: "brand-preview.js" });
      dispatch(doc, event("DOMContentLoaded", true), doc, win);
    } else if (step.do === "pick" || step.do === "restore") {
      const target = doc.querySelector("input[name=\"" + step.name + "\"][value=\"" + step.value + "\"]");
      if (!target) { throw new Error("no " + step.name + " radio " + step.value); }
      target.checked = true;
      if (step.do === "pick") {
        dispatch(target, event("input", true), doc, win);
        dispatch(target, event("change", true), doc, win);
      }
    } else if (step.do === "pageshow") {
      dispatch(win, event("pageshow", false, { persisted: step.persisted }), doc, win);
    } else if (step.do === "look") {
      looks.push(look(doc));
    } else {
      throw new Error("unknown step " + step.do);
    }
  }
  process.stdout.write(JSON.stringify(looks));
});
`

// brandTokens are the 23 color tokens a theme's palette sets, as ui.css names them.
var brandTokens = []string{
	"canvas", "surface", "subtle", "line", "line-strong", "ink", "ink-muted",
	"brand", "brand-strong", "on-brand", "brand-soft",
	"danger", "danger-strong", "on-danger", "danger-soft", "danger-ink",
	"positive-soft", "positive-ink", "caution-soft", "caution-ink", "note-soft", "note-ink", "focus",
}

// previewPalette is a palette no theme has: each token's value is the prefix and the token's place
// in brandTokens, so "a1b0" gives canvas #a1b000 and focus #a1b022.
func previewPalette(prefix string) map[string]string {
	palette := make(map[string]string, len(brandTokens))
	for i, token := range brandTokens {
		palette[token] = fmt.Sprintf("#%s%02d", prefix, i)
	}
	return palette
}

type previewTheme struct {
	Key   string            `json:"key"`
	Light map[string]string `json:"light"`
	Dark  map[string]string `json:"dark"`
}

// The palettes the page hands the script, in the auth server's order, and the shadows ui.css gives
// a panel in each mode, which a real page in that mode has.
var (
	previewBlueberry = previewTheme{Key: "blueberry", Light: previewPalette("a1b0"), Dark: previewPalette("a1d0")}
	previewPlum      = previewTheme{Key: "plum", Light: previewPalette("c2b0"), Dark: previewPalette("c2d0")}
	previewThemes    = []previewTheme{previewBlueberry, previewPlum}
)

const (
	lightPanelShadow = "0 1px 2px rgb(16 24 40 / 0.05), 0 1px 3px rgb(16 24 40 / 0.08)"
	darkPanelShadow  = "0 1px 2px rgb(0 0 0 / 0.4)"
)

type previewStep struct {
	Do        string `json:"do"`
	Name      string `json:"name,omitempty"`
	Value     string `json:"value,omitempty"`
	Persisted bool   `json:"persisted,omitempty"`
}

type previewSample struct {
	Hidden bool              `json:"hidden"`
	Style  map[string]string `json:"style"`
}

// previewSwatch is the color each token of one SVG of a swatch is drawn in.
type previewSwatch map[string]string

type previewLook struct {
	Samples         map[string]previewSample `json:"samples"`
	StyledElsewhere []string                 `json:"styledElsewhere"`
	SwitchHidden    bool                     `json:"switchHidden"`
	NotesHidden     map[string]bool          `json:"notesHidden"`
	// Swatches holds, for the appearance cards and the theme cards, each card's swatch by the
	// card's value: one previewSwatch per mode it shows.
	Swatches map[string]map[string][]previewSwatch `json:"swatches"`
}

// previewPage is the editor the stand-in document draws: the theme cards, which are the listed
// themes' and need not be, the theme checked (none when it is no card's) and the appearance.
type previewPage struct {
	themeCards []string
	theme      string
	appearance string
}

func runBrandPreview(t *testing.T, page previewPage, steps ...previewStep) []previewLook {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatalf("node is not on PATH: this test runs a page script under Node, which the dev container and " +
			"the test jobs install at the version src/authserver/versions.yaml pins")
	}
	script, err := fs.ReadFile(StaticFS(), "pages/brand-preview.js")
	if err != nil {
		t.Fatalf("reading the served script: %v", err)
	}
	program := filepath.Join(t.TempDir(), "brand-preview-run.js")
	if writeErr := os.WriteFile(program, []byte(brandPreviewRun), 0o600); writeErr != nil {
		t.Fatalf("writing the program: %v", writeErr)
	}
	input, err := json.Marshal(map[string]any{
		"script":     string(script),
		"palettes":   previewThemes,
		"themeCards": page.themeCards,
		"theme":      page.theme,
		"appearance": page.appearance,
		"steps":      steps,
	})
	require.NoError(t, err)

	cmd := exec.CommandContext(t.Context(), node, program)
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if runErr := cmd.Run(); runErr != nil {
		t.Fatalf("running the script under Node: %v: %s", runErr, strings.TrimSpace(stderr.String()))
	}
	var looks []previewLook
	if decodeErr := json.Unmarshal(stdout.Bytes(), &looks); decodeErr != nil {
		t.Fatalf("reading Node's answer: %v: %s", decodeErr, stdout.String())
	}
	return looks
}

func load() previewStep   { return previewStep{Do: "load"} }
func lookAt() previewStep { return previewStep{Do: "look"} }
func pick(name, value string) previewStep {
	return previewStep{Do: "pick", Name: name, Value: value}
}
func restore(name, value string) previewStep {
	return previewStep{Do: "restore", Name: name, Value: value}
}

// assertSampleDrawn holds a sample to exactly its mode's palette of the theme, its mode's shadow
// and color-scheme, and nothing else.
func assertSampleDrawn(t *testing.T, sample previewSample, palette map[string]string, mode string) {
	t.Helper()
	want := map[string]string{"color-scheme": mode, "--shadow-panel": lightPanelShadow}
	if mode == "dark" {
		want["--shadow-panel"] = darkPanelShadow
	}
	for token, value := range palette {
		want["--color-"+token] = value
	}
	assert.Equal(t, want, sample.Style)
}

var bothCards = []string{"blueberry", "plum"}

// Each sample is drawn in its own mode of the theme the form holds: its 23 tokens, its shadow and
// its color-scheme set on it and on no other element, so the editor around it keeps the console's
// own brand. Only the light one shows, the switch starting on Light.
func TestBrandPreviewJS_DrawsEachModesSampleInTheChosenTheme(t *testing.T) {
	looks := runBrandPreview(t, previewPage{themeCards: bothCards, theme: "plum", appearance: "auto"},
		lookAt(), load(), lookAt())

	before := looks[0]
	assert.True(t, before.Samples["light"].Hidden, "a sample is hidden until styled")
	assert.True(t, before.Samples["dark"].Hidden, "a sample is hidden until styled")

	after := looks[1]
	require.Contains(t, after.Samples, "light")
	require.Contains(t, after.Samples, "dark")
	assert.Equal(t, "#c2b000", after.Samples["light"].Style["--color-canvas"], "Plum's light canvas")
	assert.Equal(t, "#c2d022", after.Samples["dark"].Style["--color-focus"], "Plum's dark focus")
	assertSampleDrawn(t, after.Samples["light"], previewPlum.Light, "light")
	assertSampleDrawn(t, after.Samples["dark"], previewPlum.Dark, "dark")
	assert.False(t, after.Samples["light"].Hidden)
	assert.True(t, after.Samples["dark"].Hidden)
	assert.Empty(t, after.StyledElsewhere, "only the samples are styled")
}

// Picking another theme draws both samples in it at once.
func TestBrandPreviewJS_FollowsTheThemePicked(t *testing.T) {
	looks := runBrandPreview(t, previewPage{themeCards: bothCards, theme: "blueberry", appearance: "auto"},
		load(), lookAt(), pick("theme", "plum"), lookAt(), pick("theme", "blueberry"), lookAt())

	assert.Equal(t, "#a1b000", looks[0].Samples["light"].Style["--color-canvas"], "Blueberry's light canvas")
	assertSampleDrawn(t, looks[0].Samples["light"], previewBlueberry.Light, "light")
	assertSampleDrawn(t, looks[0].Samples["dark"], previewBlueberry.Dark, "dark")

	assert.Equal(t, "#c2b007", looks[1].Samples["light"].Style["--color-brand"], "Plum's light brand")
	assertSampleDrawn(t, looks[1].Samples["light"], previewPlum.Light, "light")
	assertSampleDrawn(t, looks[1].Samples["dark"], previewPlum.Dark, "dark")

	assertSampleDrawn(t, looks[2].Samples["light"], previewBlueberry.Light, "light")
	assertSampleDrawn(t, looks[2].Samples["dark"], previewBlueberry.Dark, "dark")
	for i, look := range looks {
		assert.Empty(t, look.StyledElsewhere, "look %d: only the samples are styled", i)
	}
}

// The Light/Dark switch shows one sample at a time, each still in its own mode's palette.
func TestBrandPreviewJS_TheSwitchShowsOneModeAtATime(t *testing.T) {
	looks := runBrandPreview(t, previewPage{themeCards: bothCards, theme: "blueberry", appearance: "auto"},
		load(), pick("brandPreviewMode", "dark"), lookAt(), pick("theme", "plum"), lookAt(),
		pick("brandPreviewMode", "light"), lookAt())

	assert.True(t, looks[0].Samples["light"].Hidden)
	assert.False(t, looks[0].Samples["dark"].Hidden)
	assertSampleDrawn(t, looks[0].Samples["dark"], previewBlueberry.Dark, "dark")

	assert.False(t, looks[1].Samples["dark"].Hidden, "a theme picked keeps the mode")
	assert.Equal(t, "#c2d000", looks[1].Samples["dark"].Style["--color-canvas"], "Plum's dark canvas")
	assertSampleDrawn(t, looks[1].Samples["dark"], previewPlum.Dark, "dark")

	assert.False(t, looks[2].Samples["light"].Hidden)
	assert.True(t, looks[2].Samples["dark"].Hidden)
	assertSampleDrawn(t, looks[2].Samples["light"], previewPlum.Light, "light")
}

// A form holding a theme the auth server does not list, as a refused form drawn again can, is
// previewed in the first listed theme, as its Appearance cards are drawn: whether no theme card is
// checked, or a checked card's theme has no palette.
func TestBrandPreviewJS_AThemeTheListLacksIsDrawnInTheFirst(t *testing.T) {
	looks := runBrandPreview(t, previewPage{themeCards: bothCards, theme: "", appearance: "light"},
		load(), lookAt())
	assertSampleDrawn(t, looks[0].Samples["light"], previewBlueberry.Light, "light")
	assertSampleDrawn(t, looks[0].Samples["dark"], previewBlueberry.Dark, "dark")
	assert.False(t, looks[0].Samples["light"].Hidden)

	looks = runBrandPreview(t, previewPage{themeCards: []string{"plum", "dragonfruit"}, theme: "dragonfruit", appearance: "auto"},
		load(), lookAt(), pick("theme", "plum"), lookAt(), pick("theme", "dragonfruit"), lookAt())
	assertSampleDrawn(t, looks[0].Samples["light"], previewBlueberry.Light, "light")
	assertSampleDrawn(t, looks[1].Samples["light"], previewPlum.Light, "light")
	assertSampleDrawn(t, looks[2].Samples["light"], previewBlueberry.Light, "light")
	assertSampleDrawn(t, looks[2].Samples["dark"], previewBlueberry.Dark, "dark")
}

// A browser restoring the form, as on Back, fires no input: the theme and the mode it restores are
// drawn on pageshow, whether the page came from the back-forward cache or was loaded again.
func TestBrandPreviewJS_PageshowDrawsTheRestoredForm(t *testing.T) {
	for _, persisted := range []bool{true, false} {
		t.Run(fmt.Sprintf("persisted=%v", persisted), func(t *testing.T) {
			looks := runBrandPreview(t, previewPage{themeCards: bothCards, theme: "blueberry", appearance: "auto"},
				load(), restore("theme", "plum"), restore("brandPreviewMode", "dark"), lookAt(),
				previewStep{Do: "pageshow", Persisted: persisted}, lookAt())

			assertSampleDrawn(t, looks[0].Samples["light"], previewBlueberry.Light, "light")
			assert.False(t, looks[0].Samples["light"].Hidden, "nothing is drawn before pageshow")

			assert.True(t, looks[1].Samples["light"].Hidden)
			assert.False(t, looks[1].Samples["dark"].Hidden)
			assertSampleDrawn(t, looks[1].Samples["dark"], previewPlum.Dark, "dark")
			assertSampleDrawn(t, looks[1].Samples["light"], previewPlum.Light, "light")
		})
	}
}

// The shadows the samples are given are the ones ui.css gives a panel in each mode, so a sample's
// card is drawn as a real page's in that mode.
func TestBrandPreviewJS_ShadowsAreUICSSs(t *testing.T) {
	source, err := os.ReadFile("tailwindcss/ui.css")
	require.NoError(t, err)
	css := string(source)
	assert.Contains(t, css, "  --shadow-panel: "+lightPanelShadow+";\n", "the light panel shadow")
	assert.Contains(t, css, "      --shadow-panel: "+darkPanelShadow+";\n", "the dark panel shadow, under the dark variant")
}

// shownMode is the sample a look shows: "light", "dark", "none" or "both".
func shownMode(look previewLook) string {
	light, dark := !look.Samples["light"].Hidden, !look.Samples["dark"].Hidden
	switch {
	case light && dark:
		return "both"
	case light:
		return "light"
	case dark:
		return "dark"
	}
	return "none"
}

// shownNotes are the sentences on the appearance a look shows.
func shownNotes(look previewLook) []string {
	shown := []string{}
	for _, appearance := range []string{"auto", "light", "dark"} {
		if hidden, ok := look.NotesHidden[appearance]; ok && !hidden {
			shown = append(shown, appearance)
		}
	}
	return shown
}

// The appearance decides the modes the preview shows (#811 decision 2): Automatic the switch,
// starting on Light, and the sample it names; Light and Dark their one sample and no switch. The
// sentence beside the preview says which applies. A form drawn with no appearance it knows, as a
// refused one can be, is previewed as Automatic, the appearance a new brand starts with.
func TestBrandPreviewJS_TheAppearanceDecidesTheModesShown(t *testing.T) {
	for _, tc := range []struct {
		appearance   string
		wantMode     string
		switchHidden bool
		wantNotes    []string
	}{
		{appearance: "auto", wantMode: "light", switchHidden: false, wantNotes: []string{"auto"}},
		{appearance: "light", wantMode: "light", switchHidden: true, wantNotes: []string{"light"}},
		{appearance: "dark", wantMode: "dark", switchHidden: true, wantNotes: []string{"dark"}},
		{appearance: "", wantMode: "light", switchHidden: false, wantNotes: []string{"auto"}},
	} {
		t.Run("drawn as "+tc.appearance, func(t *testing.T) {
			looks := runBrandPreview(t, previewPage{themeCards: bothCards, theme: "plum", appearance: tc.appearance},
				load(), lookAt())
			assert.Equal(t, tc.wantMode, shownMode(looks[0]))
			assert.Equal(t, tc.switchHidden, looks[0].SwitchHidden)
			assert.Equal(t, tc.wantNotes, shownNotes(looks[0]))
			assertSampleDrawn(t, looks[0].Samples["light"], previewPlum.Light, "light")
			assertSampleDrawn(t, looks[0].Samples["dark"], previewPlum.Dark, "dark")
		})
	}
}

// Changing the appearance changes the preview at once. Light and Dark show their one sample
// whatever the switch is on; back on Automatic the switch shows again, where it was left.
func TestBrandPreviewJS_PickingAnAppearanceChangesThePreview(t *testing.T) {
	looks := runBrandPreview(t, previewPage{themeCards: bothCards, theme: "blueberry", appearance: "auto"},
		load(), pick("appearance", "dark"), lookAt(), pick("appearance", "light"), lookAt(),
		pick("appearance", "auto"), lookAt(), pick("brandPreviewMode", "dark"), lookAt(),
		pick("appearance", "light"), lookAt(), pick("appearance", "auto"), lookAt())

	want := []struct {
		mode         string
		switchHidden bool
		note         string
	}{
		{"dark", true, "dark"},
		{"light", true, "light"},
		{"light", false, "auto"},
		{"dark", false, "auto"},
		{"light", true, "light"},
		{"dark", false, "auto"},
	}
	require.Len(t, looks, len(want))
	for i, w := range want {
		assert.Equal(t, w.mode, shownMode(looks[i]), "look %d: the sample shown", i)
		assert.Equal(t, w.switchHidden, looks[i].SwitchHidden, "look %d: the switch hidden", i)
		assert.Equal(t, []string{w.note}, shownNotes(looks[i]), "look %d: the sentence shown", i)
		assertSampleDrawn(t, looks[i].Samples[w.mode], map[string]map[string]string{
			"light": previewBlueberry.Light, "dark": previewBlueberry.Dark}[w.mode], w.mode)
		assert.Empty(t, looks[i].StyledElsewhere, "look %d: only the samples are styled", i)
	}
}

// swatchIn is the swatch of a palette as the brand_swatch partial draws it: its canvas, a card on
// it with its line, two lines of text and a button.
func swatchIn(palette map[string]string) previewSwatch {
	swatch := previewSwatch{}
	for _, token := range []string{"canvas", "surface", "line", "ink", "ink-muted", "brand"} {
		swatch[token] = palette[token]
	}
	return swatch
}

// assertAppearanceSwatches holds the three Appearance cards to the theme's palettes: Automatic its
// light and its dark one, Light its light one, Dark its dark one.
func assertAppearanceSwatches(t *testing.T, look previewLook, theme previewTheme, msg string) {
	t.Helper()
	assert.Equal(t, map[string][]previewSwatch{
		"auto":  {swatchIn(theme.Light), swatchIn(theme.Dark)},
		"light": {swatchIn(theme.Light)},
		"dark":  {swatchIn(theme.Dark)},
	}, look.Swatches["appearance"], msg)
}

// The three Appearance cards' swatches are drawn in the theme the form holds, on load and on every
// theme picked, and in the first listed theme for a theme the list lacks (#811 decision 4). Each
// theme card's own swatch shows its fixed theme, as the server drew it.
func TestBrandPreviewJS_TheAppearanceSwatchesFollowTheTheme(t *testing.T) {
	looks := runBrandPreview(t, previewPage{themeCards: []string{"blueberry", "plum", "dragonfruit"}, theme: "plum", appearance: "dark"},
		lookAt(), load(), lookAt(), pick("theme", "blueberry"), lookAt(), pick("theme", "plum"), lookAt(),
		pick("theme", "dragonfruit"), lookAt())

	stale := previewSwatch{"canvas": "#5e7a1e", "surface": "#5e7a1e", "line": "#5e7a1e", "ink": "#5e7a1e",
		"ink-muted": "#5e7a1e", "brand": "#5e7a1e"}
	assert.Equal(t, []previewSwatch{stale, stale}, looks[0].Swatches["appearance"]["auto"], "the page as the server drew it")

	assert.Equal(t, "#c2b000", looks[1].Swatches["appearance"]["light"][0]["canvas"], "Plum's light canvas")
	assert.Equal(t, "#c2d003", looks[1].Swatches["appearance"]["dark"][0]["line"], "Plum's dark line, the card's border")
	assertAppearanceSwatches(t, looks[1], previewPlum, "on load, the theme the form holds")
	assertAppearanceSwatches(t, looks[2], previewBlueberry, "Blueberry picked")
	assertAppearanceSwatches(t, looks[3], previewPlum, "Plum picked again")
	assertAppearanceSwatches(t, looks[4], previewBlueberry, "a theme the list lacks, in the first listed")

	for i, look := range looks {
		for _, key := range []string{"blueberry", "plum", "dragonfruit"} {
			assert.Equal(t, []previewSwatch{stale, stale}, look.Swatches["theme"][key], "look %d: %s's card keeps its own swatch", i, key)
		}
		assert.Empty(t, look.StyledElsewhere, "look %d: the swatches' colors are attributes, never styles", i)
	}
}

// A browser restoring the form, as on Back, fires no input: the appearance and theme it restores
// decide the sample, the switch, the sentence and the Appearance swatches on pageshow.
func TestBrandPreviewJS_PageshowDrawsTheRestoredAppearance(t *testing.T) {
	for _, persisted := range []bool{true, false} {
		t.Run(fmt.Sprintf("persisted=%v", persisted), func(t *testing.T) {
			looks := runBrandPreview(t, previewPage{themeCards: bothCards, theme: "blueberry", appearance: "light"},
				load(), restore("appearance", "auto"), restore("theme", "plum"), restore("brandPreviewMode", "dark"), lookAt(),
				previewStep{Do: "pageshow", Persisted: persisted}, lookAt(),
				restore("appearance", "light"), previewStep{Do: "pageshow", Persisted: persisted}, lookAt())

			assert.Equal(t, "light", shownMode(looks[0]), "nothing is drawn before pageshow")
			assert.True(t, looks[0].SwitchHidden)
			assertAppearanceSwatches(t, looks[0], previewBlueberry, "nothing is drawn before pageshow")

			assert.Equal(t, "dark", shownMode(looks[1]))
			assert.False(t, looks[1].SwitchHidden)
			assert.Equal(t, []string{"auto"}, shownNotes(looks[1]))
			assertAppearanceSwatches(t, looks[1], previewPlum, "the restored theme")

			assert.Equal(t, "light", shownMode(looks[2]))
			assert.True(t, looks[2].SwitchHidden)
			assert.Equal(t, []string{"light"}, shownNotes(looks[2]))
			assertSampleDrawn(t, looks[2].Samples["light"], previewPlum.Light, "light")
		})
	}
}
