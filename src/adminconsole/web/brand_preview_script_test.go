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
// draw keeps it. The form ends with the footer's three rows, each a label, a URL and a label per
// built-in language, and the support contact's three fields, and each sample ends with its footer
// under the card, drawn hidden and empty, as the brand_sample partial draws it (#814). It
// loads the served brand-preview.js into it, then acts as a person and a browser do: picking a
// theme or a mode (a radio checked, then its input and change events, which bubble), a browser
// restoring the form with no event, and pageshow. At each "look" it writes down what each sample
// shows, every style property any element carries, which of the switch and the sentences show,
// the colors each card's swatch is drawn in, token by token, and each sample's footer: whether it
// shows, on a panel or not, its links' text and the elements holding them, and each contact value
// shown. A person typing is a field's value set, then its input event, which bubbles.
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
  removeChild(child) { this.children = this.children.filter(function (c) { return c !== child; }); child.parentNode = null; return child; }
  replaceChildren() {
    for (const c of this.children) { c.parentNode = null; }
    this.children = [];
    for (const c of arguments) { this.appendChild(c); }
  }
  remove() { if (this.parentNode) { this.parentNode.removeChild(this); } }
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
  get lang() { return this.getAttribute("lang") || ""; }
  get classList() {
    const self = this;
    const names = function () { return (self.getAttribute("class") || "").split(/\s+/).filter(Boolean); };
    return {
      contains: function (c) { return names().indexOf(c) >= 0; },
      toggle: function (c, force) {
        const has = names().indexOf(c) >= 0;
        const on = force === undefined ? !has : !!force;
        if (on && !has) { self.setAttribute("class", names().concat([c]).join(" ")); }
        if (!on && has) { self.setAttribute("class", names().filter(function (n) { return n !== c; }).join(" ")); }
        return on;
      },
    };
  }
  get name() { return this.getAttribute("name") || ""; }
  get type() { return this.getAttribute("type") || ""; }
  get value() { return this.getAttribute("value") || ""; }
  set value(v) { this.setAttribute("value", v); }
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
  constructor() { super(); this.readyState = "interactive"; this.documentElement = null; this.adoptedStyleSheets = []; }
  get body() { return this.documentElement.children[1]; }
  getElementById(id) { return this.querySelector("#" + id); }
  createElement(tag) { return new Element(this, tag); }
}

class Window extends Node {}

// A constructed stylesheet and document.adoptedStyleSheets, as far as a page script uses them: a
// sheet is the CSS text it was last given.
class CSSStyleSheet {
  constructor() { this.cssText = ""; }
  replaceSync(text) { this.cssText = String(text); }
}

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
  const withText = function (e, text) { e.textContent = text; return e; };
  const radio = function (name, value, checked) {
    const attrs = { type: "radio", id: name + "-" + value, name: name, value: value };
    if (checked) { attrs.checked = ""; }
    return el("input", attrs);
  };
  const sample = function (mode) {
    return el("div", { class: "brand-sample", "data-brand-sample": mode, hidden: "", inert: "", "aria-hidden": "true" }, [
      el("div", { class: "panel auth-card" }, [el("div", { class: "panel-body" }, [
        el("div", { class: "auth-logo", hidden: "" }),
        el("p", { class: "auth-brand" }), el("p", { class: "auth-title" }), el("p", { class: "auth-lead" }),
        el("div", { class: "stacked" }, [
          el("div", { class: "notice notice-danger" }),
          el("div", { class: "field" }, [el("span", { class: "control" })]),
          el("div", { class: "field" }, [el("span", { class: "control", "aria-invalid": "true" })]),
          el("div", { class: "auth-actions" }, [el("span", { class: "button" }), el("span", { class: "button button-primary" })]),
        ]),
      ])]),
      el("div", { class: "brand-footer", "data-brand-sample-footer": "", hidden: "" }, [
        el("ul", { class: "brand-footer-links", hidden: "" }),
        el("p", { class: "brand-footer-contact", hidden: "" }, [
          withText(el("span"), "Need help?"),
          el("span", { class: "brand-footer-link", "data-brand-sample-contact": "email", hidden: "" }),
          el("span", { class: "brand-footer-link", "data-brand-sample-contact": "phone", hidden: "" }),
          withText(el("span", { class: "brand-footer-link", "data-brand-sample-contact": "url", hidden: "" }), "Support page"),
        ]),
      ]),
    ]);
  };
  // A text field of the form, holding what the request says it holds.
  const footer = request.footer || {};
  const field = function (id, attrs) {
    return el("input", Object.assign({ class: "control", id: id, name: id, value: footer[id] || "" }, attrs || {}));
  };
  // The footer's rows and the support contact, as the editor draws them (#814 decision 11).
  const footerFields = [];
  for (let row = 0; row < 3; row++) {
    const prefix = "footerLinks-" + row + "-";
    footerFields.push(el("fieldset", { class: "footer-link", id: "footerLinks-" + row }, [
      field(prefix + "label", { type: "text" }),
      field(prefix + "url", { type: "url" }),
      el("details", { class: "disclosure" }, ["en", "pt-BR", "es", "fr", "de", "it"].map(function (tag) {
        return field(prefix + "labels-" + tag, { type: "text", lang: tag });
      })),
    ]));
  }
  footerFields.push(field("supportEmail", { type: "email" }), field("supportUrl", { type: "url" }), field("supportPhone", { type: "tel" }));
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
  const kitStyles = el("script", { type: "application/json", id: "brand-kit-styles" });
  kitStyles.textContent = JSON.stringify(request.kitStyles);
  // Each slot's two hidden fields, as the brand_asset partial draws them: the asset's id and URL, or
  // empty.
  const slotFields = [];
  for (const slot of ["logo", "darkLogo", "favicon", "background", "regularFont", "boldFont"]) {
    const held = (request.slots || {})[slot] || { id: "", url: "" };
    slotFields.push(el("input", { type: "hidden", name: slot, value: held.id }));
    slotFields.push(el("input", { type: "hidden", name: slot + "Url", value: held.url }));
  }
  // The font select: its value is the option the form holds, as a browser answers it.
  const fontSelect = el("select", { class: "control", id: "font", name: "font", value: request.font },
    request.fonts.map(function (font) { return el("option", { value: font }); }));
  const html = el("html", { lang: request.lang || "en" }, [
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
          el("fieldset", {}, ["square", "rounded", "pill"].map(function (corners) {
            return el("label", { class: "choice" }, [radio("corners", corners, request.corners === corners)]);
          })),
          el("div", { class: "field" }, [fontSelect]),
          el("fieldset", {}, ["cover", "contain", "tile"].map(function (fit) {
            return el("label", { class: "choice" }, [radio("backgroundFit", fit, request.backgroundFit === fit)]);
          })),
          el("label", { class: "check-row" }, [el("input", Object.assign({ type: "checkbox", id: "hideAppName", name: "hideAppName" },
            request.hideAppName ? { checked: "" } : {}))]),
        ].concat(slotFields).concat(footerFields)),
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
      kitStyles,
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

// sampleFooter answers what a sample's footer shows: whether it shows, whether on the panel, its links
// as their text and the elements holding it, and each contact value's text, null while hidden.
function sampleFooter(footer) {
  const list = footer.querySelector(".brand-footer-links");
  const contact = footer.querySelector(".brand-footer-contact");
  const shown = function (kind) {
    const value = contact.querySelector("[data-brand-sample-contact=\"" + kind + "\"]");
    return value.hidden ? null : value.textContent;
  };
  return {
    hidden: footer.hidden,
    panel: footer.classList.contains("brand-footer-panel"),
    linksHidden: list.hidden,
    links: list.children.map(function (item) {
      return {
        text: item.textContent,
        element: item.tagName.toLowerCase() + ">" + item.children.map(function (c) {
          return c.tagName.toLowerCase() + "." + (c.getAttribute("class") || "").split(/\s+/).join(".") + (c.children.length ? ">" + c.children.length : "");
        }).join(","),
      };
    }),
    contactHidden: contact.hidden,
    needHelp: contact.children[0].textContent,
    email: shown("email"),
    phone: shown("phone"),
    url: shown("url"),
  };
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
    const box = s.querySelector(".auth-logo");
    const images = box.querySelectorAll("img");
    samples[s.getAttribute("data-brand-sample")] = {
      hidden: s.hidden, style: Object.assign({}, s.styleProps),
      logo: { hidden: box.hidden, images: images.map(function (img) { return { src: img.getAttribute("src"), alt: img.getAttribute("alt") }; }) },
      nameHidden: s.querySelector(".auth-brand").hidden,
      footer: sampleFooter(s.querySelector("[data-brand-sample-footer]")),
    };
  }
  const styledElsewhere = [];
  for (const n of [doc.documentElement].concat(doc.documentElement.descendants())) {
    if (!n.hasAttribute("data-brand-sample") && Object.keys(n.styleProps).length > 0) {
      styledElsewhere.push(n.describe + " " + JSON.stringify(n.styleProps));
    }
  }
  return {
    samples: samples,
    fontSheets: doc.adoptedStyleSheets.map(function (sheet) { return sheet.cssText; }),
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
  const context = { document: doc, window: win, console: console, JSON: JSON, Object: Object, CSSStyleSheet: CSSStyleSheet };
  win.document = doc;
  vm.createContext(context);
  for (const step of request.steps) {
    if (step.do === "load") {
      vm.runInContext(request.script, context, { filename: "brand-preview.js" });
      dispatch(doc, event("DOMContentLoaded", true), doc, win);
    } else if ((step.do === "pick" || step.do === "restore") && step.name === "font") {
      // A family chosen in the select, as a person or a browser restoring the form does.
      const target = doc.getElementById("font");
      target.setAttribute("value", step.value);
      if (step.do === "pick") {
        dispatch(target, event("input", true), doc, win);
        dispatch(target, event("change", true), doc, win);
      }
    } else if (step.do === "pick" || step.do === "restore") {
      const target = doc.querySelector("input[name=\"" + step.name + "\"][value=\"" + step.value + "\"]");
      if (!target) { throw new Error("no " + step.name + " radio " + step.value); }
      target.checked = true;
      if (step.do === "pick") {
        dispatch(target, event("input", true), doc, win);
        dispatch(target, event("change", true), doc, win);
      }
    } else if (step.do === "slot" || step.do === "restoreSlot") {
      // A file uploaded or removed, as brand-assets.js puts it in the slot's hidden fields and tells
      // the page, or the fields as a browser restores them, telling nothing.
      const idField = doc.querySelector("input[name=\"" + step.name + "\"]");
      doc.querySelector("input[name=\"" + step.name + "Url\"]").setAttribute("value", step.url || "");
      idField.setAttribute("value", step.value || "");
      if (step.do === "slot") { dispatch(idField, event("input", true), doc, win); }
    } else if (step.do === "type" || step.do === "restoreValue") {
      // A text field typed in, or filled by a browser restoring the form, telling nothing.
      const target = doc.getElementById(step.name);
      if (!target) { throw new Error("no field " + step.name); }
      target.setAttribute("value", step.value || "");
      if (step.do === "type") { dispatch(target, event("input", true), doc, win); }
    } else if (step.do === "check") {
      const box = doc.getElementById(step.name);
      box.checked = step.value === "on";
      dispatch(box, event("input", true), doc, win);
      dispatch(box, event("change", true), doc, win);
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
	URL       string `json:"url,omitempty"`
	Persisted bool   `json:"persisted,omitempty"`
}

// previewImage is an image the sample's logo box holds.
type previewImage struct {
	Src string `json:"src"`
	Alt string `json:"alt"`
}

// previewLogo is a sample's logo box: whether it shows, and the images in it.
type previewLogo struct {
	Hidden bool           `json:"hidden"`
	Images []previewImage `json:"images"`
}

type previewSample struct {
	Hidden     bool              `json:"hidden"`
	Style      map[string]string `json:"style"`
	Logo       previewLogo       `json:"logo"`
	NameHidden bool              `json:"nameHidden"`
	Footer     previewFooter     `json:"footer"`
}

// previewFooterLink is a link of a sample's footer: its text, and the elements holding it, such as
// "li>span.brand-footer-link", an item holding one span of that class with no element in it.
type previewFooterLink struct {
	Text    string `json:"text"`
	Element string `json:"element"`
}

// previewFooter is a sample's footer under its card (#814): whether it shows and on the panel, its
// links, and the contact line, each value's text or nil while it is hidden.
type previewFooter struct {
	Hidden        bool                `json:"hidden"`
	Panel         bool                `json:"panel"`
	LinksHidden   bool                `json:"linksHidden"`
	Links         []previewFooterLink `json:"links"`
	ContactHidden bool                `json:"contactHidden"`
	NeedHelp      string              `json:"needHelp"`
	Email         *string             `json:"email"`
	Phone         *string             `json:"phone"`
	URL           *string             `json:"url"`
}

// previewSlot is what a slot's hidden fields hold: an asset's id and URL.
type previewSlot struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

// previewSwatch is the color each token of one SVG of a swatch is drawn in.
type previewSwatch map[string]string

type previewLook struct {
	Samples         map[string]previewSample `json:"samples"`
	FontSheets      []string                 `json:"fontSheets"`
	StyledElsewhere []string                 `json:"styledElsewhere"`
	SwitchHidden    bool                     `json:"switchHidden"`
	NotesHidden     map[string]bool          `json:"notesHidden"`
	// Swatches holds, for the appearance cards and the theme cards, each card's swatch by the
	// card's value: one previewSwatch per mode it shows.
	Swatches map[string]map[string][]previewSwatch `json:"swatches"`
}

// previewPage is the editor the stand-in document draws: the theme cards, which are the listed
// themes' and need not be, the theme checked (none when it is no card's), the appearance, the corner
// shape checked (none when it is no radio's), the family the font select holds, the fit checked, the
// switch hiding the app name, the files the slots hold, by slot, the page's language, "en" when
// empty, and what the footer's fields hold, by id.
type previewPage struct {
	themeCards    []string
	theme         string
	appearance    string
	corners       string
	font          string
	backgroundFit string
	hideAppName   bool
	slots         map[string]previewSlot
	lang          string
	footer        map[string]string
}

// previewKitStyles is what the page hands the script for each corner shape and family, in values no
// brand draws, so a sample drawn from anything but the data block cannot pass.
var previewKitStyles = map[string]any{
	"corners": map[string]map[string]string{
		"square": {"control": "0", "panel": "0"},
		"pill":   {"control": "91px", "panel": "17px"},
	},
	"fonts": map[string]string{
		"humanist": "Testhumanist, sans-serif",
		"serif":    "Testserif, 'Test Serif Two', serif",
		"uploaded": `"brand-font", Testsystem, sans-serif`,
	},
	"uploadedFamily": `"brand-font"`,
	"fontWeights":    map[string]string{"regular": "1 450", "bold": "451 1000"},
	"backgrounds": map[string]map[string]string{
		"cover":   {"size": "testcover", "position": "testcenter", "repeat": "testonce"},
		"contain": {"size": "testcontain", "position": "testmiddle", "repeat": "testonce"},
		"tile":    {"size": "", "position": "", "repeat": "testrepeat"},
	},
}

// previewFonts are the font select's options, as the page draws them.
var previewFonts = []string{"system-ui", "humanist", "geometric", "serif", "neo-grotesque", "rounded", "uploaded"}

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
		"script":        string(script),
		"palettes":      previewThemes,
		"themeCards":    page.themeCards,
		"theme":         page.theme,
		"appearance":    page.appearance,
		"corners":       page.corners,
		"font":          page.font,
		"backgroundFit": page.backgroundFit,
		"hideAppName":   page.hideAppName,
		"slots":         page.slots,
		"lang":          page.lang,
		"footer":        page.footer,
		"fonts":         previewFonts,
		"kitStyles":     previewKitStyles,
		"steps":         steps,
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

// upload puts the asset id with url in slot, as brand-assets.js does once a file is uploaded, and
// remove empties it, as Remove does.
func upload(slot, id, url string) previewStep {
	return previewStep{Do: "slot", Name: slot, Value: id, URL: url}
}
func remove(slot string) previewStep { return previewStep{Do: "slot", Name: slot} }

// check turns the switch named on or off, as a click does.
func check(name string, on bool) previewStep {
	value := "off"
	if on {
		value = "on"
	}
	return previewStep{Do: "check", Name: name, Value: value}
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

// assertSampleDrawnWithKit holds a sample to its mode's palette, shadow and color-scheme, as
// assertSampleDrawn does, and to exactly the kit's tokens in kit, and nothing else.
func assertSampleDrawnWithKit(t *testing.T, sample previewSample, palette map[string]string, mode string, kit map[string]string, msg string) {
	t.Helper()
	want := map[string]string{"color-scheme": mode, "--shadow-panel": lightPanelShadow}
	if mode == "dark" {
		want["--shadow-panel"] = darkPanelShadow
	}
	for token, value := range palette {
		want["--color-"+token] = value
	}
	for token, value := range kit {
		want[token] = value
	}
	assert.Equal(t, want, sample.Style, msg)
}

// The sample takes the corners and the family as they are picked, before anything is saved (#813):
// square and pill set the two radius tokens the stylesheet sets for them, a family its font-family
// list, on both samples and on no other element. Rounded and System UI are today's look, the console's
// own, so picking them back takes the tokens off again.
func TestBrandPreviewJS_TheSampleTakesTheCornersAndTheFamilyPicked(t *testing.T) {
	looks := runBrandPreview(t, previewPage{themeCards: bothCards, theme: "plum", appearance: "auto", corners: "rounded", font: "system-ui"},
		load(), lookAt(),
		pick("corners", "square"), lookAt(),
		pick("corners", "pill"), lookAt(),
		pick("font", "serif"), lookAt(),
		pick("corners", "rounded"), lookAt(),
		pick("font", "system-ui"), lookAt())

	pill := map[string]string{"--radius-control": "91px", "--radius-panel": "17px"}
	serif := map[string]string{"--font-sans": "Testserif, 'Test Serif Two', serif"}
	want := []struct {
		kit map[string]string
		msg string
	}{
		{map[string]string{}, "drawn rounded in System UI, nothing set"},
		{map[string]string{"--radius-control": "0", "--radius-panel": "0"}, "square picked"},
		{pill, "pill picked"},
		{map[string]string{"--radius-control": "91px", "--radius-panel": "17px", "--font-sans": "Testserif, 'Test Serif Two', serif"}, "serif picked, pill kept"},
		{serif, "rounded picked again, serif kept"},
		{map[string]string{}, "System UI picked again"},
	}
	require.Len(t, looks, len(want))
	for i, w := range want {
		assertSampleDrawnWithKit(t, looks[i].Samples["light"], previewPlum.Light, "light", w.kit, w.msg)
		assertSampleDrawnWithKit(t, looks[i].Samples["dark"], previewPlum.Dark, "dark", w.kit, w.msg)
		assert.Empty(t, looks[i].StyledElsewhere, "look %d: only the samples are styled", i)
	}
}

// A brand's page is drawn with its stored corners and family, which the sample takes on load; the
// uploaded font is drawn with the list the page hands for it.
func TestBrandPreviewJS_TheSampleTakesTheStoredCornersAndFamilyOnLoad(t *testing.T) {
	looks := runBrandPreview(t, previewPage{themeCards: bothCards, theme: "blueberry", appearance: "dark", corners: "pill", font: "uploaded"},
		lookAt(), load(), lookAt())

	assert.Empty(t, looks[0].Samples["dark"].Style, "nothing is drawn before the script runs")
	kit := map[string]string{"--radius-control": "91px", "--radius-panel": "17px", "--font-sans": `"brand-font", Testsystem, sans-serif`}
	assertSampleDrawnWithKit(t, looks[1].Samples["dark"], previewBlueberry.Dark, "dark", kit, "the stored pill and uploaded font")
	assertSampleDrawnWithKit(t, looks[1].Samples["light"], previewBlueberry.Light, "light", kit, "the stored pill and uploaded font")
}

// A form holding a corner shape or a family the page hands nothing for, as a refused form drawn
// again can, draws the sample as today: rounded, in System UI. A family named like a property every
// object has is no family either.
func TestBrandPreviewJS_ACornerShapeOrFamilyWithNothingHandedDrawsTodaysLook(t *testing.T) {
	for _, page := range []previewPage{
		{corners: "", font: "comic"},
		{corners: "", font: "constructor"},
		{corners: "", font: "geometric"},
		{corners: "", font: ""},
	} {
		t.Run(page.font, func(t *testing.T) {
			page.themeCards, page.theme, page.appearance = bothCards, "plum", "light"
			looks := runBrandPreview(t, page, load(), lookAt())
			assertSampleDrawn(t, looks[0].Samples["light"], previewPlum.Light, "light")
			assertSampleDrawn(t, looks[0].Samples["dark"], previewPlum.Dark, "dark")
		})
	}

	// Pill picked, then a family with nothing handed: the radii stay, and the family is taken off.
	looks := runBrandPreview(t, previewPage{themeCards: bothCards, theme: "plum", appearance: "light", corners: "rounded", font: "humanist"},
		load(), lookAt(), pick("corners", "pill"), pick("font", "toString"), lookAt())
	assertSampleDrawnWithKit(t, looks[0].Samples["light"], previewPlum.Light, "light",
		map[string]string{"--font-sans": "Testhumanist, sans-serif"}, "the stored humanist")
	assertSampleDrawnWithKit(t, looks[1].Samples["light"], previewPlum.Light, "light",
		map[string]string{"--radius-control": "91px", "--radius-panel": "17px"}, "no family handed for toString")
}

// A browser restoring the form, as on Back, fires no input: the corners and the family it restores are
// drawn on pageshow.
func TestBrandPreviewJS_PageshowDrawsTheRestoredCornersAndFamily(t *testing.T) {
	looks := runBrandPreview(t, previewPage{themeCards: bothCards, theme: "plum", appearance: "auto", corners: "rounded", font: "system-ui"},
		load(), restore("corners", "square"), restore("font", "humanist"), lookAt(),
		previewStep{Do: "pageshow", Persisted: true}, lookAt())

	assertSampleDrawn(t, looks[0].Samples["light"], previewPlum.Light, "light")
	kit := map[string]string{"--radius-control": "0", "--radius-panel": "0", "--font-sans": "Testhumanist, sans-serif"}
	assertSampleDrawnWithKit(t, looks[1].Samples["light"], previewPlum.Light, "light", kit, "the restored square and humanist")
	assertSampleDrawnWithKit(t, looks[1].Samples["dark"], previewPlum.Dark, "dark", kit, "the restored square and humanist")
}

// The sample reads the tokens the script sets: ui.css rounds a sample's multi-line boxes from its own
// --radius-control, as :root does a page's, and draws its text in its own --font-sans.
func TestBrandPreviewJS_TheSampleReadsTheKitsTokens(t *testing.T) {
	source, err := os.ReadFile("tailwindcss/ui.css")
	require.NoError(t, err)
	css := string(source)
	start := strings.Index(css, "  .brand-sample {\n")
	require.GreaterOrEqual(t, start, 0, "the sample's rule")
	end := strings.Index(css[start:], "\n  }\n")
	require.Positive(t, end)
	rule := css[start : start+end+1]
	assert.Contains(t, rule, "    --radius-box: min(var(--radius-control), 1rem);\n")
	assert.Contains(t, rule, "    font-family: var(--font-sans);\n")
}

// The files a slot can hold in these tests, at URLs no asset has.
const (
	testLogoURL       = "https://login.example.test/brand-assets/21?v=light"
	testDarkLogoURL   = "https://login.example.test/brand-assets/22?v=dark"
	testBackgroundURL = "https://login.example.test/brand-assets/24?v=back"
	testRegularURL    = "https://login.example.test/brand-assets/25?v=regular"
	testBoldURL       = "https://login.example.test/brand-assets/26?v=bold"
)

// logoOf is the one image a sample's logo box shows, or "" when it shows none.
func logoOf(t *testing.T, sample previewSample) string {
	t.Helper()
	if sample.Logo.Hidden {
		assert.Empty(t, sample.Logo.Images, "a hidden logo box holds no image")
		return ""
	}
	require.Len(t, sample.Logo.Images, 1, "a logo box shows one image")
	assert.Empty(t, sample.Logo.Images[0].Alt, "the sample is an illustration, so its logo has an empty alt")
	return sample.Logo.Images[0].Src
}

// The sample draws the logo of its mode above the app name, as a sign-in card does (#813 decision 5):
// the light sample the logo, and the dark one the dark logo, or the logo while there is none. A file
// uploaded is drawn at once, a stored one on load, and a removed one is taken off.
func TestBrandPreviewJS_TheSampleDrawsTheLogoOfEachMode(t *testing.T) {
	looks := runBrandPreview(t, previewPage{themeCards: bothCards, theme: "plum", appearance: "auto",
		slots: map[string]previewSlot{"logo": {ID: "21", URL: testLogoURL}}},
		lookAt(), load(), lookAt(),
		upload("darkLogo", "22", testDarkLogoURL), lookAt(),
		remove("logo"), lookAt(),
		remove("darkLogo"), lookAt())

	assert.True(t, looks[0].Samples["light"].Logo.Hidden, "nothing is drawn before the script runs")
	want := []struct {
		light, dark string
		msg         string
	}{
		{testLogoURL, testLogoURL, "the stored logo, in both modes while there is no dark logo"},
		{testLogoURL, testDarkLogoURL, "a dark logo uploaded is the dark sample's"},
		{"", testDarkLogoURL, "the logo removed: the dark logo stays where it is drawn"},
		{"", "", "both removed"},
	}
	for i, w := range want {
		look := looks[i+1]
		assert.Equal(t, w.light, logoOf(t, look.Samples["light"]), "light: %s", w.msg)
		assert.Equal(t, w.dark, logoOf(t, look.Samples["dark"]), "dark: %s", w.msg)
		assert.False(t, look.Samples["light"].NameHidden, "the name is shown: %s", w.msg)
		assert.Empty(t, look.StyledElsewhere, "look %d: only the samples are styled", i+1)
	}
}

// The switch hides the app name beside a logo, and has no effect without one, so the name never
// disappears with nothing in its place (#813 decision 5).
func TestBrandPreviewJS_TheSwitchHidesTheNameOnlyBesideALogo(t *testing.T) {
	looks := runBrandPreview(t, previewPage{themeCards: bothCards, theme: "plum", appearance: "auto", hideAppName: true},
		load(), lookAt(),
		upload("logo", "21", testLogoURL), lookAt(),
		check("hideAppName", false), lookAt(),
		check("hideAppName", true), remove("logo"), lookAt())

	for _, mode := range []string{"light", "dark"} {
		assert.False(t, looks[0].Samples[mode].NameHidden, "%s: no logo, so the name is shown though the switch is on", mode)
		assert.True(t, looks[1].Samples[mode].NameHidden, "%s: a logo and the switch on", mode)
		assert.Equal(t, testLogoURL, logoOf(t, looks[1].Samples[mode]))
		assert.False(t, looks[2].Samples[mode].NameHidden, "%s: the switch off", mode)
		assert.False(t, looks[3].Samples[mode].NameHidden, "%s: the logo removed", mode)
	}
}

// The sample draws the background image behind its card over its canvas, laid out at the fit the form
// holds as the page hands each fit's layout (#813 decision 6), and follows the fit as it is picked. A
// fit's empty value is no property. Removing the image takes it off again.
func TestBrandPreviewJS_TheSampleDrawsTheBackgroundAtItsFit(t *testing.T) {
	looks := runBrandPreview(t, previewPage{themeCards: bothCards, theme: "plum", appearance: "light", backgroundFit: "cover"},
		load(), lookAt(),
		upload("background", "24", testBackgroundURL), lookAt(),
		pick("backgroundFit", "contain"), lookAt(),
		pick("backgroundFit", "tile"), lookAt(),
		remove("background"), lookAt())

	image := `url("` + testBackgroundURL + `")`
	want := []struct {
		kit map[string]string
		msg string
	}{
		{map[string]string{}, "no background"},
		{map[string]string{"background-image": image, "background-size": "testcover", "background-position": "testcenter", "background-repeat": "testonce"}, "uploaded, at cover"},
		{map[string]string{"background-image": image, "background-size": "testcontain", "background-position": "testmiddle", "background-repeat": "testonce"}, "contain picked"},
		{map[string]string{"background-image": image, "background-repeat": "testrepeat"}, "tile picked"},
		{map[string]string{}, "removed"},
	}
	require.Len(t, looks, len(want))
	for i, w := range want {
		assertSampleDrawnWithKit(t, looks[i].Samples["light"], previewPlum.Light, "light", w.kit, w.msg)
		assertSampleDrawnWithKit(t, looks[i].Samples["dark"], previewPlum.Dark, "dark", w.kit, w.msg)
		assert.Empty(t, looks[i].StyledElsewhere, "look %d: only the samples are styled", i)
	}
}

// A fit the page hands nothing for, as a refused form drawn again can hold, lays the image out as
// cover, as the auth server draws it.
func TestBrandPreviewJS_ABackgroundAtAFitWithNothingHandedIsCover(t *testing.T) {
	looks := runBrandPreview(t, previewPage{themeCards: bothCards, theme: "plum", appearance: "light", backgroundFit: "stretch",
		slots: map[string]previewSlot{"background": {ID: "24", URL: testBackgroundURL}}},
		load(), lookAt())
	assertSampleDrawnWithKit(t, looks[0].Samples["light"], previewPlum.Light, "light", map[string]string{
		"background-image": `url("` + testBackgroundURL + `")`, "background-size": "testcover",
		"background-position": "testcenter", "background-repeat": "testonce"}, "drawn as cover")
}

// The uploaded font is declared in the page under the family its list names first, swapped in once it
// loads (#813 decision 7), by the @font-face rules the auth server's stylesheet declares it with: one
// regular file with no weight, so a browser gives a variable font its own weight range and a static
// one its synthesized bold, or with a bold file, each for the weights the page hands. The rules are in
// one stylesheet the page adopts once. Nothing is declared while another family is chosen or no
// regular file is there, and a face no longer used is taken out of the page.
func TestBrandPreviewJS_TheSampleDeclaresTheUploadedFont(t *testing.T) {
	looks := runBrandPreview(t, previewPage{themeCards: bothCards, theme: "plum", appearance: "light", font: "uploaded"},
		load(), lookAt(),
		upload("regularFont", "25", testRegularURL), lookAt(),
		upload("boldFont", "26", testBoldURL), lookAt(),
		pick("font", "serif"), lookAt(),
		pick("font", "uploaded"), remove("boldFont"), lookAt(),
		remove("regularFont"), lookAt())

	regularAlone := "@font-face {\n" +
		"  font-family: \"brand-font\";\n" +
		"  src: url(\"" + testRegularURL + "\") format(\"woff2\");\n" +
		"  font-display: swap;\n" +
		"}\n"
	regularAndBold := "@font-face {\n" +
		"  font-family: \"brand-font\";\n" +
		"  src: url(\"" + testRegularURL + "\") format(\"woff2\");\n" +
		"  font-weight: 1 450;\n" +
		"  font-display: swap;\n" +
		"}\n" +
		"@font-face {\n" +
		"  font-family: \"brand-font\";\n" +
		"  src: url(\"" + testBoldURL + "\") format(\"woff2\");\n" +
		"  font-weight: 451 1000;\n" +
		"  font-display: swap;\n" +
		"}\n"
	want := [][]string{
		{},
		{regularAlone},
		{regularAndBold},
		{""},
		{regularAlone},
		{""},
	}
	require.Len(t, looks, len(want))
	for i, sheets := range want {
		assert.Equal(t, sheets, looks[i].FontSheets, "look %d: the stylesheets the page adopts and their rules", i)
	}
	assert.Equal(t, `"brand-font", Testsystem, sans-serif`, looks[2].Samples["light"].Style["--font-sans"], "the sample's text in the uploaded font")
	assert.Equal(t, "Testserif, 'Test Serif Two', serif", looks[3].Samples["light"].Style["--font-sans"])
}

// A browser restoring the form, as on Back, fills the slots' fields and fires nothing: what they hold
// is drawn on pageshow.
func TestBrandPreviewJS_PageshowDrawsTheRestoredFiles(t *testing.T) {
	looks := runBrandPreview(t, previewPage{themeCards: bothCards, theme: "plum", appearance: "dark", font: "uploaded", backgroundFit: "tile"},
		load(),
		previewStep{Do: "restoreSlot", Name: "logo", Value: "21", URL: testLogoURL},
		previewStep{Do: "restoreSlot", Name: "background", Value: "24", URL: testBackgroundURL},
		previewStep{Do: "restoreSlot", Name: "regularFont", Value: "25", URL: testRegularURL},
		lookAt(), previewStep{Do: "pageshow", Persisted: false}, lookAt())

	assert.Empty(t, logoOf(t, looks[0].Samples["dark"]), "nothing is drawn before pageshow")
	assert.Empty(t, looks[0].FontSheets)
	assert.Equal(t, testLogoURL, logoOf(t, looks[1].Samples["dark"]))
	assert.Equal(t, `url("`+testBackgroundURL+`")`, looks[1].Samples["dark"].Style["background-image"])
	require.Len(t, looks[1].FontSheets, 1)
	assert.Contains(t, looks[1].FontSheets[0], `src: url("`+testRegularURL+`") format("woff2");`)
}

// A slot whose id field is empty holds nothing, whatever its URL field holds.
func TestBrandPreviewJS_ASlotWithoutAnIdHoldsNothing(t *testing.T) {
	looks := runBrandPreview(t, previewPage{themeCards: bothCards, theme: "plum", appearance: "light", font: "uploaded",
		slots: map[string]previewSlot{"logo": {URL: testLogoURL}, "background": {URL: testBackgroundURL}, "regularFont": {URL: testRegularURL}}},
		load(), lookAt())
	assert.Empty(t, logoOf(t, looks[0].Samples["light"]))
	assert.Empty(t, looks[0].Samples["light"].Style["background-image"])
	assert.Empty(t, looks[0].FontSheets)
}
