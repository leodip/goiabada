package web

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// brandPaletteRun is the program the TestBrandPaletteJS tests run under Node (#815 decisions 7 and 8).
// It draws the brand editor's Colors section in the stand-in document, as
// admin_settings_branding_brand.html draws it from the handler's view: the theme cards with Custom
// last, the appearance cards, the section drawn hidden unless Custom is checked, the Basic and Advanced
// choice, the note on going back to Basic, Copy colors from with its status line, the lines about a
// column the appearance hides, and a row per color, each with a Light and a Dark cell holding a color
// well, drawn hidden, and the #rrggbb text field the form sends, with its message. The server's
// drawing rules are the template's: a row Basic does not show is hidden, a column is shown while the
// appearance draws it or a field of a shown row in it is not a color, and such a field is marked. It
// loads the served brand-palette.js, then acts as a person and a browser do: a radio picked (its input
// and change events, which bubble), a field typed in or a color picked in a well (input), a theme
// chosen in a select (change), a button clicked, the form restored with no event, and pageshow. At
// each "look" it writes down what shows and what each field and well holds.
//
// The live check (#815 decision 6) runs on a clock and a network of the program's own. The section
// names the console's check route, and under it the warnings region holds the count line, the
// sentence for colors that could not be checked, and the list of a saved brand's failing pairs when
// the page has one. A timer runs only when a "wait" step moves the clock past it. Each request the
// script sends is written down and waits for an "answer" step, which hands it a status and a JSON
// body, or a "fail" step, which fails it as a network does; the program then lets every promise
// settle. A "look" also writes down the requests sent, the warnings region as it shows, how many
// input events the script dispatched on the section to tell the page it wrote the fields, and every
// navigation to the session-ended route.
const brandPaletteRun = `"use strict";
` + standInDOM + `

const colorPattern = /^#[0-9a-fA-F]{6}$/;

function build(request) {
  const doc = new Document();
  const win = new Window();
  const el = function (tag, attrs, children) {
    const e = new Element(doc, tag, attrs);
    for (const c of children || []) { e.appendChild(c); }
    return e;
  };
  const hiddenIf = function (attrs, hidden) { if (hidden) { attrs.hidden = ""; } return attrs; };
  const radio = function (name, value, checked) {
    const attrs = { type: "radio", id: name + "-" + value, name: name, value: value };
    if (checked) { attrs.checked = ""; }
    return el("input", attrs);
  };
  const basicTokens = ["canvas", "surface", "ink", "brand"];
  const basic = request.mode !== "advanced";
  const rowShown = function (token) { return !basic || basicTokens.indexOf(token) >= 0; };
  const drawn = { light: request.appearance !== "dark", dark: request.appearance !== "light" };
  const values = { light: request.light, dark: request.dark };
  const shown = {};
  for (const mode of ["light", "dark"]) {
    shown[mode] = drawn[mode] || request.tokens.some(function (token) {
      return rowShown(token) && !colorPattern.test(values[mode][token]);
    });
  }
  const cell = function (mode, token) {
    const id = "palette-" + mode + "-" + token;
    const value = values[mode][token];
    const invalid = !colorPattern.test(value);
    const text = { class: "control palette-value", type: "text", id: id, name: id, value: value,
      "aria-labelledby": "palette-label-" + token + " palette-head-" + mode, "data-palette-value": "" };
    if (invalid) { text["aria-invalid"] = "true"; text["aria-describedby"] = id + "-error"; }
    return el("div", hiddenIf({ class: "palette-cell", "data-palette-column": mode }, !shown[mode]), [
      el("div", { class: "palette-control" }, [
        el("input", { type: "color", class: "palette-well", id: id + "-well", value: invalid ? "#000000" : value.toLowerCase(),
          "data-palette-well": "", hidden: "" }),
        el("input", text),
      ]),
      el("p", hiddenIf({ class: "field-error", id: id + "-error" }, !invalid)),
    ]);
  };
  const rows = request.tokens.map(function (token) {
    const attrs = { class: "palette-row", "data-palette-row": token };
    if (basicTokens.indexOf(token) >= 0) { attrs["data-palette-basic"] = ""; } else { attrs["data-palette-advanced"] = ""; }
    return el("div", hiddenIf(attrs, !rowShown(token)), [
      el("span", { class: "palette-label", id: "palette-label-" + token }, [
        el("code", hiddenIf({ class: "palette-token", "data-palette-advanced": "" }, basic)),
      ]),
      cell("light", token),
      cell("dark", token),
    ]);
  });
  const note = function (name, hidden) { return el("p", hiddenIf({ class: "field-hint", "data-palette-note": name }, hidden)); };
  const themeCard = function (key) {
    return el("label", { class: "option-card" }, [radio("theme", key, key === request.theme)]);
  };
  const status = el("p", { class: "field-hint", id: "paletteCopyStatus", role: "status", "data-copied": "Colors copied." });
  const copyFrom = el("select", { class: "control", id: "paletteCopyFrom", value: request.themeCards[0] },
    request.themeCards.map(function (key) { return el("option", { value: key }); }));
  // The warnings region, as the template draws it: hidden and empty, or a saved brand's list.
  const saved = request.warnings;
  const count = el("p", { class: "palette-warnings-count", id: "paletteWarningsCount", role: "status" });
  count.textContent = saved ? saved.countLine : "";
  const regionChildren = [count];
  if (saved && saved.items.length > 0) {
    regionChildren.push(el("ul", { class: "palette-warning-list", "aria-labelledby": "paletteWarningsCount" }, saved.items.map(function (item) {
      const text = el("span");
      text.textContent = item.text;
      return el("li", { class: "palette-warning", "data-palette-warning-mode": item.mode }, [
        el("svg", { class: "palette-warning-swatch", viewBox: "0 0 40 24" }, [el("rect", { fill: item.background }), el("rect", { fill: item.foreground })]),
        text,
      ]);
    })));
  }
  const region = el("div", hiddenIf({ class: "palette-warnings", id: "palette-warnings", "data-unchecked": uncheckedLine }, !saved), regionChildren);
  const section = el("fieldset", hiddenIf({ class: "palette-editor", id: "brand-palette", "data-palette-stored-mode": request.storedMode || "",
    "data-palette-check-url": "/admin/settings/branding/palette-check" }, request.theme !== "custom"), [
    el("input", { type: "hidden", name: "paletteFresh", value: request.fresh ? "true" : "" }),
    el("fieldset", {}, [radio("paletteMode", "basic", request.mode === "basic"), radio("paletteMode", "advanced", request.mode === "advanced")]),
    el("div", hiddenIf({ class: "notice notice-note", "data-palette-basic-note": "" }, !(basic && request.storedMode === "advanced"))),
    el("div", { class: "field", "data-palette-copy": "", hidden: "" }, [
      copyFrom,
      el("button", { class: "button", type: "button", id: "paletteCopy" }),
      status,
    ]),
    note("unused-light", shown.light), note("invalid-light", !(shown.light && !drawn.light)),
    note("unused-dark", shown.dark), note("invalid-dark", !(shown.dark && !drawn.dark)),
    el("div", { class: "palette-grid" }, [
      el("div", { class: "palette-row palette-head" }, [
        el("span", hiddenIf({ class: "palette-cell field-label", id: "palette-head-light", "data-palette-column": "light" }, !shown.light)),
        el("span", hiddenIf({ class: "palette-cell field-label", id: "palette-head-dark", "data-palette-column": "dark" }, !shown.dark)),
      ]),
      el("div", { class: "palette-group" }, [el("p", hiddenIf({ class: "palette-group-name", "data-palette-advanced": "" }, basic))].concat(rows)),
    ]),
    region,
  ]);
  const palettes = el("script", { type: "application/json", id: "brand-palettes" });
  palettes.textContent = JSON.stringify(request.palettes);
  const html = el("html", { lang: "en" }, [
    el("head"),
    el("body", {}, [el("main", { id: "main" }, [
      el("form", { class: "panel", method: "post" }, [
        el("input", { class: "control", id: "name", type: "text", name: "name", value: "Autumn" }),
        el("fieldset", {}, ["auto", "light", "dark"].map(function (value) {
          return el("label", { class: "option-card" }, [radio("appearance", value, request.appearance === value)]);
        })),
        el("fieldset", {}, request.themeCards.concat(["custom"]).map(themeCard)),
        section,
      ]),
      palettes,
    ])]),
  ]);
  doc.appendChild(html);
  doc.documentElement = html;
  doc.defaultView = win;
  return { doc: doc, win: win };
}

// The sentence the region says when the colors could not be checked.
const uncheckedLine = "The colors could not be checked. They are checked when the brand is saved.";

// The program's clock: each timer, and the time now, in milliseconds.
let now = 0;
let timers = [];
let nextTimer = 1;
function setTimeout(fn, delay) {
  const id = nextTimer++;
  timers.push({ id: id, at: now + Math.max(0, Number(delay) || 0), fn: fn });
  return id;
}
function clearTimeout(id) { timers = timers.filter(function (t) { return t.id !== id; }); }
function wait(ms) {
  const until = now + (Number(ms) || 0);
  for (;;) {
    const due = timers.filter(function (t) { return t.at <= until; }).sort(function (a, b) { return a.at - b.at || a.id - b.id; })[0];
    if (!due) { break; }
    timers = timers.filter(function (t) { return t !== due; });
    now = due.at;
    due.fn();
  }
  now = until;
}

// The program's network: each request sent, and how it is settled.
const requests = [];
function fetch(url, init) {
  return new Promise(function (resolve, reject) {
    requests.push({ url: String(url), method: init.method, headers: Object.assign({}, init.headers),
      body: Object.fromEntries(new URLSearchParams(String(init.body))), resolve: resolve, reject: reject });
  });
}

// utils.js's helpers the script calls, as utils.js defines them for a page with no CSRF field and
// whose catalog is English; the session-ended route is written down rather than gone to.
const navigations = [];
function scriptRequestHeaders(extra) { return Object.assign({ "X-Requested-With": "XMLHttpRequest" }, extra); }
function withPageLanguage(url) { return url + "?ui_locales=en"; }
function isSessionEnded(err) { return err !== null && typeof err === "object" && err.error === "session_ended"; }
function goToSessionEnded() { navigations.push("/auth/session-ended"); }

function look(doc) {
  const rows = {};
  for (const row of doc.querySelectorAll("[data-palette-row]")) { rows[row.getAttribute("data-palette-row")] = row.hidden; }
  const columns = {};
  for (const mode of ["light", "dark"]) {
    const cells = doc.querySelectorAll("div.palette-cell[data-palette-column=\"" + mode + "\"]");
    columns[mode] = { shown: cells.filter(function (c) { return !c.hidden; }).length, hidden: cells.filter(function (c) { return c.hidden; }).length };
  }
  const notes = {};
  for (const n of doc.querySelectorAll("[data-palette-note]")) { notes[n.getAttribute("data-palette-note")] = n.hidden; }
  const fields = {};
  for (const f of doc.querySelectorAll("[data-palette-value]")) {
    const well = doc.getElementById(f.id + "-well");
    fields[f.id] = {
      value: f.value,
      invalid: f.getAttribute("aria-invalid") === "true",
      describedBy: f.getAttribute("aria-describedby") || "",
      errorHidden: doc.getElementById(f.id + "-error").hidden,
      well: well.value,
      wellHidden: well.hidden,
    };
  }
  const marks = doc.querySelectorAll("[data-palette-advanced]").filter(function (m) { return !m.hasAttribute("data-palette-row"); });
  const region = doc.getElementById("palette-warnings");
  const list = region.querySelector("ul.palette-warning-list");
  return {
    requests: requests.map(function (r) { return { url: r.url, method: r.method, headers: r.headers, body: r.body }; }),
    warnings: {
      hidden: region.hidden,
      count: doc.getElementById("paletteWarningsCount").textContent,
      countRole: doc.getElementById("paletteWarningsCount").getAttribute("role"),
      list: list ? list.getAttribute("aria-labelledby") : null,
      items: list ? list.children.map(function (item) {
        const svg = item.querySelector("svg");
        return {
          mode: item.getAttribute("data-palette-warning-mode"),
          class: item.getAttribute("class"),
          text: item.querySelector("span").textContent,
          swatch: svg.getAttribute("class") + " " + svg.getAttribute("viewBox") + " " + svg.getAttribute("aria-hidden") + " " + svg.namespaceURI,
          fills: svg.querySelectorAll("rect").map(function (r) { return r.getAttribute("fill"); }),
        };
      }) : [],
    },
    sectionInputs: sectionInputs,
    navigations: navigations.slice(),
    sectionHidden: doc.getElementById("brand-palette").hidden,
    fresh: doc.querySelector("input[name=\"paletteFresh\"]").value,
    rows: rows,
    advancedMarksShown: marks.filter(function (m) { return !m.hidden; }).length,
    columns: columns,
    notes: notes,
    basicNoteHidden: doc.querySelector("[data-palette-basic-note]").hidden,
    copyHidden: doc.querySelector("[data-palette-copy]").hidden,
    status: doc.getElementById("paletteCopyStatus").textContent,
    fields: fields,
  };
}

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", function (chunk) { input += chunk; });
// How many input events were dispatched on the section itself, which only a script does.
let sectionInputs = 0;

// settle lets every promise the script chained run.
function settle() { return new Promise(function (resolve) { setImmediate(resolve); }); }

process.stdin.on("end", async function () {
  const request = JSON.parse(input);
  const page = build(request);
  const doc = page.doc;
  const win = page.win;
  const looks = [];
  const context = { document: doc, window: win, console: console, JSON: JSON, Object: Object, Event: Event,
    URLSearchParams: URLSearchParams, setTimeout: setTimeout, clearTimeout: clearTimeout, fetch: fetch,
    scriptRequestHeaders: scriptRequestHeaders, withPageLanguage: withPageLanguage,
    isSessionEnded: isSessionEnded, goToSessionEnded: goToSessionEnded };
  win.document = doc;
  vm.createContext(context);
  doc.addEventListener("input", function (e) { if (e.target === doc.getElementById("brand-palette")) { sectionInputs++; } });
  for (const step of request.steps) {
    if (step.do === "wait") {
      wait(step.ms);
    } else if (step.do === "answer") {
      const sent = requests[step.index];
      if (!sent) { throw new Error("no request " + step.index); }
      const body = step.body;
      sent.resolve({ ok: step.status >= 200 && step.status < 300, status: step.status,
        json: function () { return Promise.resolve(JSON.parse(JSON.stringify(body))); } });
    } else if (step.do === "fail") {
      const sent = requests[step.index];
      if (!sent) { throw new Error("no request " + step.index); }
      sent.reject(new TypeError("Failed to fetch"));
    } else if (step.do === "load") {
      vm.runInContext(request.script, context, { filename: "brand-palette.js" });
      dispatch(doc, event("DOMContentLoaded", true), doc, win);
    } else if (step.do === "pick" || step.do === "restore") {
      const target = doc.querySelector("input[name=\"" + step.name + "\"][value=\"" + step.value + "\"]");
      if (!target) { throw new Error("no " + step.name + " radio " + step.value); }
      target.checked = true;
      if (step.do === "pick") {
        dispatch(target, event("input", true), doc, win);
        dispatch(target, event("change", true), doc, win);
      }
    } else if (step.do === "type" || step.do === "restoreValue" || step.do === "well") {
      // A text field typed in, a color picked in a well, or a field a browser restores, telling nothing.
      const target = doc.getElementById(step.name);
      if (!target) { throw new Error("no field " + step.name); }
      target.setAttribute("value", step.value || "");
      if (step.do !== "restoreValue") { dispatch(target, event("input", true), doc, win); }
    } else if (step.do === "choose") {
      const target = doc.getElementById(step.name);
      target.setAttribute("value", step.value);
      dispatch(target, event("change", true), doc, win);
    } else if (step.do === "click") {
      const target = doc.getElementById(step.name);
      if (!target) { throw new Error("no button " + step.name); }
      dispatch(target, event("click", true), doc, win);
    } else if (step.do === "pageshow") {
      dispatch(win, event("pageshow", false, { persisted: true }), doc, win);
    } else if (step.do === "look") {
      looks.push(look(doc));
    } else {
      throw new Error("unknown step " + step.do);
    }
    await settle();
  }
  process.stdout.write(JSON.stringify(looks));
});
`

// paletteColumn is how many of a column's 23 cells show and how many are hidden.
type paletteColumn struct {
	Shown  int `json:"shown"`
	Hidden int `json:"hidden"`
}

// paletteField is a text field of the Colors section and its well.
type paletteField struct {
	Value       string `json:"value"`
	Invalid     bool   `json:"invalid"`
	DescribedBy string `json:"describedBy"`
	ErrorHidden bool   `json:"errorHidden"`
	Well        string `json:"well"`
	WellHidden  bool   `json:"wellHidden"`
}

// paletteRequest is a request the script sent: its URL, method, headers and form body.
type paletteRequest struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Body    map[string]string `json:"body"`
}

// paletteWarningLook is an item of the warnings list: its mode, its class, its sentence, its swatch's
// class, viewBox, aria-hidden and namespace, and the swatch's fills, the background then the
// foreground.
type paletteWarningLook struct {
	Mode   string   `json:"mode"`
	Class  string   `json:"class"`
	Text   string   `json:"text"`
	Swatch string   `json:"swatch"`
	Fills  []string `json:"fills"`
}

// paletteWarnings is the warnings region: whether it is hidden, its count line and the line's role,
// what the list is labelled by, nil with no list, and its items.
type paletteWarnings struct {
	Hidden    bool                 `json:"hidden"`
	Count     string               `json:"count"`
	CountRole string               `json:"countRole"`
	List      *string              `json:"list"`
	Items     []paletteWarningLook `json:"items"`
}

type paletteLook struct {
	Requests           []paletteRequest         `json:"requests"`
	Warnings           paletteWarnings          `json:"warnings"`
	SectionInputs      int                      `json:"sectionInputs"`
	Navigations        []string                 `json:"navigations"`
	SectionHidden      bool                     `json:"sectionHidden"`
	Fresh              string                   `json:"fresh"`
	Rows               map[string]bool          `json:"rows"`
	AdvancedMarksShown int                      `json:"advancedMarksShown"`
	Columns            map[string]paletteColumn `json:"columns"`
	Notes              map[string]bool          `json:"notes"`
	BasicNoteHidden    bool                     `json:"basicNoteHidden"`
	CopyHidden         bool                     `json:"copyHidden"`
	Status             string                   `json:"status"`
	Fields             map[string]paletteField  `json:"fields"`
}

// paletteSaved is a saved brand's list the page is drawn with: its count line and its items.
type paletteSaved struct {
	CountLine string              `json:"countLine"`
	Items     []paletteAnswerItem `json:"items"`
}

// palettePage is the editor the stand-in draws: a saved brand's warnings, nil for none, the theme
// checked, "custom" for the Custom card, the
// appearance, the mode checked, the mode of the palette stored, whether the fields hold untouched
// theme colors, and each field's value, by mode and token.
type palettePage struct {
	warnings   *paletteSaved
	theme      string
	appearance string
	mode       string
	storedMode string
	fresh      bool
	light      map[string]string
	dark       map[string]string
}

func choose(id, value string) previewStep { return previewStep{Do: "choose", Name: id, Value: value} }
func click(id string) previewStep         { return previewStep{Do: "click", Name: id} }
func pickWell(id, value string) previewStep {
	return previewStep{Do: "well", Name: id + "-well", Value: value}
}

func runBrandPalette(t *testing.T, page palettePage, steps ...previewStep) []paletteLook {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatalf("node is not on PATH: this test runs a page script under Node, which the dev container and " +
			"the test jobs install at the version src/authserver/versions.yaml pins")
	}
	script, err := fs.ReadFile(StaticFS(), "pages/brand-palette.js")
	if err != nil {
		t.Fatalf("reading the served script: %v", err)
	}
	program := filepath.Join(t.TempDir(), "brand-palette-run.js")
	if writeErr := os.WriteFile(program, []byte(brandPaletteRun), 0o600); writeErr != nil {
		t.Fatalf("writing the program: %v", writeErr)
	}
	input, err := json.Marshal(map[string]any{
		"script":     string(script),
		"palettes":   previewThemes,
		"themeCards": []string{"blueberry", "plum"},
		"tokens":     brandTokens,
		"theme":      page.theme,
		"appearance": page.appearance,
		"mode":       page.mode,
		"storedMode": page.storedMode,
		"fresh":      page.fresh,
		"light":      page.light,
		"dark":       page.dark,
		"warnings":   page.warnings,
		"steps":      steps,
	})
	require.NoError(t, err)
	cmd := exec.CommandContext(t.Context(), node, program)
	cmd.Stdin = strings.NewReader(string(input))
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", out)
	var looks []paletteLook
	require.NoError(t, json.Unmarshal(out, &looks), "%s", out)
	return looks
}

// customPage is a stored basic palette on Custom, under Automatic, its fields holding colors no theme
// has.
func customPage() palettePage {
	return palettePage{theme: "custom", appearance: "auto", mode: "basic", storedMode: "basic",
		light: previewPalette("e1e0"), dark: previewPalette("e1d0")}
}

// rowsHidden is how many of the 23 rows are hidden.
func rowsHidden(look paletteLook) int {
	n := 0
	for _, hidden := range look.Rows {
		if hidden {
			n++
		}
	}
	return n
}

// fieldsOf answers each field's value in a mode, by token.
func fieldsOf(look paletteLook, mode string) map[string]string {
	values := map[string]string{}
	for _, token := range brandTokens {
		values[token] = look.Fields["palette-"+mode+"-"+token].Value
	}
	return values
}

// The Colors section shows while Custom is picked; picking a built-in theme hides it and keeps what
// it holds (decision 7).
func TestBrandPaletteJS_TheSectionFollowsTheCustomCard(t *testing.T) {
	page := customPage()
	page.theme = "plum"
	looks := runBrandPalette(t, page, load(), lookAt(),
		pick("theme", "custom"), lookAt(),
		pick("theme", "blueberry"), lookAt())

	assert.True(t, looks[0].SectionHidden)
	assert.False(t, looks[1].SectionHidden, "Custom picked")
	assert.True(t, looks[2].SectionHidden, "a built-in theme picked")
	assert.Equal(t, previewPalette("e1e0"), fieldsOf(looks[2], "light"), "nothing lost")
	assert.Equal(t, previewPalette("e1d0"), fieldsOf(looks[2], "dark"), "nothing lost")
}

// The first time Custom is picked for a brand with no palette, the fields take the colors of the
// built-in theme picked before it; after that, and for a brand with a palette, they keep what they
// hold (decision 7).
func TestBrandPaletteJS_TheFirstPickOfCustomTakesTheThemePickedBefore(t *testing.T) {
	fresh := palettePage{theme: "blueberry", appearance: "auto", mode: "basic", fresh: true,
		light: previewBlueberry.Light, dark: previewBlueberry.Dark}
	looks := runBrandPalette(t, fresh, load(),
		pick("theme", "plum"), pick("theme", "custom"), lookAt(),
		pick("theme", "blueberry"), pick("theme", "custom"), lookAt())

	assert.Equal(t, previewPlum.Light, fieldsOf(looks[0], "light"))
	assert.Equal(t, previewPlum.Dark, fieldsOf(looks[0], "dark"))
	assert.Equal(t, "#c2b007", looks[0].Fields["palette-light-brand"].Well, "the wells too")
	assert.Empty(t, looks[0].Fresh, "no longer untouched")
	assert.Equal(t, previewPlum.Light, fieldsOf(looks[1], "light"), "only the first time")

	stored := customPage()
	stored.theme = "plum"
	looks = runBrandPalette(t, stored, load(), pick("theme", "custom"), lookAt())
	assert.Equal(t, previewPalette("e1e0"), fieldsOf(looks[0], "light"), "a stored palette is kept")
}

// Advanced shows every row and each token's name; going back to Basic hides the other 19 again and
// says they are worked out at the save (decision 7).
func TestBrandPaletteJS_AdvancedShowsEveryRowAndBasicSaysTheOthersAreWorkedOut(t *testing.T) {
	looks := runBrandPalette(t, customPage(), load(), lookAt(),
		pick("paletteMode", "advanced"), lookAt(),
		pick("paletteMode", "basic"), lookAt())

	assert.Equal(t, 19, rowsHidden(looks[0]))
	assert.False(t, looks[0].Rows["brand"])
	assert.Zero(t, looks[0].AdvancedMarksShown)
	assert.True(t, looks[0].BasicNoteHidden)

	assert.Equal(t, 0, rowsHidden(looks[1]))
	assert.Equal(t, 24, looks[1].AdvancedMarksShown, "the group name and each of the 23 token names")
	assert.True(t, looks[1].BasicNoteHidden)

	assert.Equal(t, 19, rowsHidden(looks[2]))
	assert.Zero(t, looks[2].AdvancedMarksShown)
	assert.False(t, looks[2].BasicNoteHidden, "back to Basic says so")
	assert.Equal(t, previewPalette("e1e0"), fieldsOf(looks[2], "light"), "the values are kept")
}

// The columns follow the appearance: Light hides the Dark column and says its colors are kept and not
// used, and the reverse; Automatic shows both (decision 8).
func TestBrandPaletteJS_TheColumnsFollowTheAppearance(t *testing.T) {
	looks := runBrandPalette(t, customPage(), load(), lookAt(),
		pick("appearance", "light"), lookAt(),
		pick("appearance", "dark"), lookAt(),
		pick("appearance", "auto"), lookAt())

	both := map[string]paletteColumn{"light": {Shown: 23}, "dark": {Shown: 23}}
	noNotes := map[string]bool{"unused-light": true, "invalid-light": true, "unused-dark": true, "invalid-dark": true}
	assert.Equal(t, both, looks[0].Columns)
	assert.Equal(t, noNotes, looks[0].Notes)
	assert.Equal(t, map[string]paletteColumn{"light": {Shown: 23}, "dark": {Hidden: 23}}, looks[1].Columns)
	assert.Equal(t, map[string]bool{"unused-light": true, "invalid-light": true, "unused-dark": false, "invalid-dark": true}, looks[1].Notes)
	assert.Equal(t, map[string]paletteColumn{"light": {Hidden: 23}, "dark": {Shown: 23}}, looks[2].Columns)
	assert.Equal(t, map[string]bool{"unused-light": false, "invalid-light": true, "unused-dark": true, "invalid-dark": true}, looks[2].Notes)
	assert.Equal(t, both, looks[3].Columns)
	assert.Equal(t, noNotes, looks[3].Notes)
}

// A value that is not a color is marked at its field with its message. A column the appearance hides
// stays shown while it holds one, with the line saying its colors must be valid, and once every field
// in it is a color it hides again at the next appearance change (decision 8's exception).
func TestBrandPaletteJS_AColumnHoldingAValueThatIsNoColorStaysUntilItIsOne(t *testing.T) {
	looks := runBrandPalette(t, customPage(), load(),
		typeIn("palette-dark-brand", "#12"), lookAt(),
		pick("appearance", "light"), lookAt(),
		typeIn("palette-dark-brand", "#123456"), lookAt(),
		pick("appearance", "auto"), pick("appearance", "light"), lookAt())

	assert.Equal(t, paletteField{Value: "#12", Invalid: true, DescribedBy: "palette-dark-brand-error", Well: "#e1d007"},
		looks[0].Fields["palette-dark-brand"])

	assert.Equal(t, paletteColumn{Shown: 23}, looks[1].Columns["dark"], "kept on screen while it is not a color")
	assert.False(t, looks[1].Notes["invalid-dark"])
	assert.True(t, looks[1].Notes["unused-dark"])

	assert.Equal(t, paletteField{Value: "#123456", ErrorHidden: true, Well: "#123456"}, looks[2].Fields["palette-dark-brand"])
	assert.Equal(t, paletteColumn{Shown: 23}, looks[2].Columns["dark"], "until the next appearance change")

	assert.Equal(t, paletteColumn{Hidden: 23}, looks[3].Columns["dark"])
	assert.False(t, looks[3].Notes["unused-dark"])
	assert.True(t, looks[3].Notes["invalid-dark"])
}

// A value that is not a color in a row Basic hides does not keep its column on screen, since it is
// not sent; going to Advanced, where it is, brings the column back.
func TestBrandPaletteJS_ARowBasicHidesDoesNotKeepItsColumn(t *testing.T) {
	looks := runBrandPalette(t, customPage(), load(),
		pick("paletteMode", "advanced"), typeIn("palette-dark-focus", "blue"),
		pick("paletteMode", "basic"), pick("appearance", "light"), lookAt(),
		pick("paletteMode", "advanced"), lookAt())

	assert.Equal(t, paletteColumn{Hidden: 23}, looks[0].Columns["dark"])
	assert.Equal(t, paletteColumn{Shown: 23}, looks[1].Columns["dark"])
	assert.False(t, looks[1].Notes["invalid-dark"])
}

// The well and the text field are kept in step: a color typed is set on the well in lower case, a
// value that is not one leaves the well as it was, and a color picked in the well is written in the
// field, clearing its mark. The wells show once the script runs. An edit means the fields no longer
// hold untouched theme colors.
func TestBrandPaletteJS_TheWellAndTheFieldAreKeptInStep(t *testing.T) {
	page := customPage()
	page.fresh = true
	looks := runBrandPalette(t, page, lookAt(), load(), lookAt(),
		typeIn("palette-light-ink", "#ABCDEF"), lookAt(),
		typeIn("palette-light-ink", "abc"), lookAt(),
		pickWell("palette-light-ink", "#00ff00"), lookAt())

	assert.True(t, looks[0].Fields["palette-light-ink"].WellHidden, "drawn hidden")
	assert.False(t, looks[1].Fields["palette-light-ink"].WellHidden)
	assert.Equal(t, "true", looks[1].Fresh)
	assert.Equal(t, paletteField{Value: "#ABCDEF", ErrorHidden: true, Well: "#abcdef"}, looks[2].Fields["palette-light-ink"])
	assert.Empty(t, looks[2].Fresh)
	assert.Equal(t, paletteField{Value: "abc", Invalid: true, DescribedBy: "palette-light-ink-error", Well: "#abcdef"}, looks[3].Fields["palette-light-ink"])
	assert.Equal(t, paletteField{Value: "#00ff00", ErrorHidden: true, Well: "#00ff00"}, looks[4].Fields["palette-light-ink"])
}

// Copy colors from replaces every field of both modes with the theme's colors, clears every mark,
// asks nothing and says it was done (decision 7). It shows once the script runs.
func TestBrandPaletteJS_CopyColorsFromReplacesEveryField(t *testing.T) {
	looks := runBrandPalette(t, customPage(), lookAt(), load(), lookAt(),
		typeIn("palette-dark-ink", "nope"), pick("paletteMode", "advanced"),
		choose("paletteCopyFrom", "plum"), click("paletteCopy"), lookAt())

	assert.True(t, looks[0].CopyHidden)
	assert.False(t, looks[1].CopyHidden)
	assert.Empty(t, looks[1].Status)
	assert.Equal(t, previewPlum.Light, fieldsOf(looks[2], "light"))
	assert.Equal(t, previewPlum.Dark, fieldsOf(looks[2], "dark"))
	assert.Equal(t, paletteField{Value: "#c2d005", ErrorHidden: true, Well: "#c2d005"}, looks[2].Fields["palette-dark-ink"])
	assert.Equal(t, "Colors copied.", looks[2].Status)
}

// Copy colors from fills all 23 colors of both modes, so nothing is left to be worked out from the
// four: in Advanced, after the check of an edit of the four could not be reached, it asks as an
// advanced palette, and the copied colors stay.
func TestBrandPaletteJS_CopyColorsFromInAdvancedLeavesNothingToWorkOut(t *testing.T) {
	looks := runBrandPalette(t, customPage(), load(),
		typeIn("palette-light-canvas", "#101010"), pick("paletteMode", "advanced"), waitFor(0), failRequest(0),
		choose("paletteCopyFrom", "plum"), click("paletteCopy"), waitFor(0), answer(1, 200, workedOut()), lookAt())

	look := looks[0]
	require.Len(t, look.Requests, 2)
	assert.Equal(t, "basic", look.Requests[0].Body["paletteMode"], "the edit of the four, asked as a basic palette")
	assert.Equal(t, "advanced", look.Requests[1].Body["paletteMode"])
	assert.Equal(t, previewPlum.Light["note-ink"], look.Requests[1].Body["palette-light-note-ink"])
	assert.Equal(t, previewPlum.Light, fieldsOf(look, "light"), "the copied colors stay")
	assert.Equal(t, previewPlum.Dark, fieldsOf(look, "dark"))
	assert.Equal(t, workedOutList(), look.Warnings.Items)
}

// A browser restoring the form fires no event, so pageshow draws it again: the section, the rows and
// the columns for what the form holds, and each field's mark.
func TestBrandPaletteJS_PageshowDrawsTheRestoredForm(t *testing.T) {
	page := customPage()
	page.theme = "plum"
	looks := runBrandPalette(t, page, load(),
		restore("theme", "custom"), restore("appearance", "dark"), restore("paletteMode", "advanced"),
		restoreValue("palette-light-focus", "#1234"),
		previewStep{Do: "pageshow"}, lookAt())

	assert.False(t, looks[0].SectionHidden)
	assert.Equal(t, 0, rowsHidden(looks[0]))
	assert.Equal(t, map[string]paletteColumn{"light": {Shown: 23}, "dark": {Shown: 23}}, looks[0].Columns, "light holds a value that is no color")
	assert.False(t, looks[0].Notes["invalid-light"])
	assert.True(t, looks[0].Fields["palette-light-focus"].Invalid)
}

// The script declares nothing in the page's global scope, which brand-preview.js shares.
func TestBrandPaletteJS_DeclaresNothingGlobal(t *testing.T) {
	script, err := fs.ReadFile(StaticFS(), "pages/brand-palette.js")
	require.NoError(t, err)
	for _, line := range strings.Split(string(script), "\n") {
		if regexp.MustCompile(`^(const|let|var|function|class)\b`).MatchString(line) {
			t.Errorf("a top-level declaration: %s", line)
		}
	}
	assert.Contains(t, string(script), fmt.Sprintf("%q", "use strict"))
}

// The live check (#815 decision 6): while a custom palette is edited, the script posts the entered
// palette to the console's check route after a pause in editing, and draws the answer: the worked-out
// colors in the fields of a basic palette's other 19 rows, which the preview reads, and the failing
// pairs under their count line. It drops every answer but the one to its latest request, and says the
// colors could not be checked when the route cannot be reached.

// paletteAnswerItem is a failing pair as the check route answers it.
type paletteAnswerItem struct {
	Mode       string `json:"mode"`
	Foreground string `json:"foreground"`
	Background string `json:"background"`
	Text       string `json:"text"`
}

// paletteAnswer is the check route's answer.
type paletteAnswer struct {
	Light     map[string]string   `json:"light"`
	Dark      map[string]string   `json:"dark"`
	CountLine string              `json:"countLine"`
	Warnings  []paletteAnswerItem `json:"warnings"`
}

func waitFor(ms int) previewStep { return previewStep{Do: "wait", Ms: ms} }
func answer(index, status int, body any) previewStep {
	return previewStep{Do: "answer", Index: index, Status: status, Body: body}
}
func failRequest(index int) previewStep { return previewStep{Do: "fail", Index: index} }

const (
	checkURL     = "/admin/settings/branding/palette-check?ui_locales=en"
	uncheckedSay = "The colors could not be checked. They are checked when the brand is saved."
	twoPairsSay  = "2 pairs are below their minimum. Text and boundaries drawn in them do not meet WCAG 2.2 level AA contrast."
)

// basicRowTokens are the four rows Basic shows.
var basicRowTokens = []string{"canvas", "surface", "ink", "brand"}

// workedOut is an answer of colors no field holds, "a2e0" in light and "a2d0" in dark, with two
// failing pairs, one in each mode.
func workedOut() paletteAnswer {
	return paletteAnswer{
		Light: previewPalette("a2e0"), Dark: previewPalette("a2d0"), CountLine: twoPairsSay,
		Warnings: []paletteAnswerItem{
			{Mode: "light", Foreground: "#a2e006", Background: "#a2e010", Text: "Light: Muted text on Soft brand background, 3.91:1. Minimum 4.5:1."},
			{Mode: "dark", Foreground: "#a2d003", Background: "#a2d001", Text: "Dark: Border on Card, 2.1:1. Minimum 3:1."},
		},
	}
}

// workedOutList is workedOut's pairs as the region draws them.
func workedOutList() []paletteWarningLook {
	swatch := "palette-warning-swatch 0 0 40 24 true http://www.w3.org/2000/svg"
	return []paletteWarningLook{
		{Mode: "light", Class: "palette-warning", Text: "Light: Muted text on Soft brand background, 3.91:1. Minimum 4.5:1.",
			Swatch: swatch, Fills: []string{"#a2e010", "#a2e006"}},
		{Mode: "dark", Class: "palette-warning", Text: "Dark: Border on Card, 2.1:1. Minimum 3:1.",
			Swatch: swatch, Fills: []string{"#a2d001", "#a2d003"}},
	}
}

// basicBody is the form a basic palette's check sends: the mode, the appearance, and the four colors
// of each mode, from light and dark.
func basicBody(appearance string, light, dark map[string]string) map[string]string {
	body := map[string]string{"paletteMode": "basic", "appearance": appearance}
	for _, token := range basicRowTokens {
		body["palette-light-"+token] = light[token]
		body["palette-dark-"+token] = dark[token]
	}
	return body
}

// withColor is colors with token set to value.
func withColor(colors map[string]string, token, value string) map[string]string {
	out := map[string]string{}
	for t, v := range colors {
		out[t] = v
	}
	out[token] = value
	return out
}

// listedNone is the region as a page with no saved list draws it, untouched.
var listedNone = paletteWarnings{Hidden: true, CountRole: "status", Items: []paletteWarningLook{}}

// The script waits for a pause in editing before it asks: each edit starts the pause again, and the
// one request sent carries the palette as it then stands, the four colors of each mode of a basic
// palette as typed, with the mode and the appearance, to the console's route in the page's language,
// marked as a script's request.
func TestBrandPaletteJS_AsksAfterAPauseInEditing(t *testing.T) {
	looks := runBrandPalette(t, customPage(), load(),
		typeIn("palette-light-canvas", "#FBF7F0"), waitFor(200),
		typeIn("palette-light-ink", " #1d1a16"), waitFor(299), lookAt(),
		waitFor(1), lookAt(), waitFor(5000), lookAt())

	assert.Empty(t, looks[0].Requests, "the pause started again at the second edit")
	light := withColor(withColor(previewPalette("e1e0"), "canvas", "#FBF7F0"), "ink", "#1d1a16")
	assert.Equal(t, []paletteRequest{{URL: checkURL, Method: "POST", Headers: map[string]string{"X-Requested-With": "XMLHttpRequest"},
		Body: basicBody("auto", light, previewPalette("e1d0"))}}, looks[1].Requests)
	assert.Len(t, looks[2].Requests, 1, "one request for one pause")
	assert.Equal(t, listedNone, looks[1].Warnings, "nothing drawn before the answer")
}

// The answer is drawn: a basic palette's 19 other fields, and their wells, take the worked-out colors,
// and the page is told, so the preview draws them; the four entered colors stay as typed. The failing
// pairs are listed under their count line, the region's announced part, each beside a swatch of the
// pair, the foreground drawn on the background.
func TestBrandPaletteJS_DrawsTheAnswer(t *testing.T) {
	answered := workedOut()
	answered.Light["canvas"] = "#fbf7f0"
	looks := runBrandPalette(t, customPage(), load(),
		typeIn("palette-light-canvas", "#FBF7F0"), waitFor(300), answer(0, 200, answered), lookAt())

	look := looks[0]
	// The 19 take the answer, and the four keep what the page held or what was typed.
	entered := map[string]map[string]string{"light": withColor(previewPalette("e1e0"), "canvas", "#FBF7F0"), "dark": previewPalette("e1d0")}
	for mode, answeredColors := range map[string]map[string]string{"light": answered.Light, "dark": answered.Dark} {
		wanted := withColor(answeredColors, "canvas", entered[mode]["canvas"])
		for _, token := range basicRowTokens {
			wanted[token] = entered[mode][token]
		}
		assert.Equal(t, wanted, fieldsOf(look, mode), mode)
	}
	assert.Equal(t, "#a2e022", look.Fields["palette-light-focus"].Well, "the well follows")
	assert.Equal(t, 1, look.SectionInputs, "the page is told the fields changed")
	labelled := "paletteWarningsCount"
	assert.Equal(t, paletteWarnings{Count: twoPairsSay, CountRole: "status", List: &labelled, Items: workedOutList()}, look.Warnings)
}

// A palette with no failing pair says so, and a saved brand's list drawn by the page gives way to the
// answer.
func TestBrandPaletteJS_AnAnswerWithNoFailingPairReplacesTheSavedList(t *testing.T) {
	page := customPage()
	page.warnings = &paletteSaved{CountLine: "1 pair is below its minimum.",
		Items: []paletteAnswerItem{{Mode: "light", Foreground: "#e1e006", Background: "#e1e010", Text: "Light: Muted text on Soft brand background, 3.91:1. Minimum 4.5:1."}}}
	passing := workedOut()
	passing.CountLine = "Every pair meets its minimum."
	passing.Warnings = []paletteAnswerItem{}
	looks := runBrandPalette(t, page, load(), lookAt(),
		typeIn("palette-dark-ink", "#f2ede6"), waitFor(300), answer(0, 200, passing), lookAt())

	assert.Len(t, looks[0].Warnings.Items, 1, "the saved list, as the page drew it")
	assert.Equal(t, paletteWarnings{Count: "Every pair meets its minimum.", CountRole: "status", Items: []paletteWarningLook{}}, looks[1].Warnings)
}

// Only the answer to the latest request is drawn: an answer to an earlier one arriving after it is
// dropped, and so is one arriving after an edit that has not been sent yet, whose own request follows
// the pause.
func TestBrandPaletteJS_DropsAStaleAnswer(t *testing.T) {
	older := workedOut()
	older.Light = previewPalette("b1e0")
	older.CountLine = "Older."
	looks := runBrandPalette(t, customPage(), load(),
		typeIn("palette-light-canvas", "#111111"), waitFor(300),
		typeIn("palette-light-canvas", "#222222"), waitFor(300),
		answer(1, 200, workedOut()), answer(0, 200, older), lookAt())

	require.Len(t, looks[0].Requests, 2)
	assert.Equal(t, "#222222", looks[0].Requests[1].Body["palette-light-canvas"])
	assert.Equal(t, "#a2e022", fieldsOf(looks[0], "light")["focus"], "the latest answer's colors")
	assert.Equal(t, twoPairsSay, looks[0].Warnings.Count)

	looks = runBrandPalette(t, customPage(), load(),
		typeIn("palette-light-canvas", "#111111"), waitFor(300),
		typeIn("palette-light-canvas", "#222222"), answer(0, 200, workedOut()), lookAt(),
		waitFor(300), lookAt())

	assert.Equal(t, previewPalette("e1e0")["focus"], fieldsOf(looks[0], "light")["focus"], "an answer to colors since changed is dropped")
	assert.Equal(t, listedNone, looks[0].Warnings)
	assert.Zero(t, looks[0].SectionInputs)
	require.Len(t, looks[1].Requests, 2)
	assert.Equal(t, "#222222", looks[1].Requests[1].Body["palette-light-canvas"])
}

// When the route cannot be reached, the network failing, the sign-in having ended, or anything but
// its answer coming back, the region says the colors could not be checked and are checked when the
// brand is saved, listing nothing; the fields, which the sample is drawn from, keep the entered
// colors, and the page stays where it is, the form unsaved.
func TestBrandPaletteJS_SaysWhenTheColorsCouldNotBeChecked(t *testing.T) {
	for name, settle := range map[string]previewStep{
		"the network failed": failRequest(0),
		"the sign-in ended": answer(0, 403, map[string]string{"error": "session_ended",
			"error_description": "Your sign-in has ended. Sign in again."}),
		"a refusal": answer(0, 400, map[string]string{"error": "handler.brand.palette_color_invalid",
			"error_description": "The palette's light canvas color must be # and six hexadecimal digits, such as #2456c4."}),
		"a server fault":           answer(0, 500, map[string]string{"error": "server_error", "error_description": "An unexpected server error has occurred."}),
		"an answer with no colors": answer(0, 200, map[string]string{"countLine": "Every pair meets its minimum."}),
	} {
		t.Run(name, func(t *testing.T) {
			page := customPage()
			page.warnings = &paletteSaved{CountLine: "1 pair is below its minimum.",
				Items: []paletteAnswerItem{{Mode: "light", Foreground: "#e1e006", Background: "#e1e010", Text: "Light: Muted text on Soft brand background, 3.91:1. Minimum 4.5:1."}}}
			looks := runBrandPalette(t, page, load(),
				typeIn("palette-light-canvas", "#111111"), waitFor(300), settle, lookAt())

			look := looks[0]
			assert.Equal(t, paletteWarnings{Count: uncheckedSay, CountRole: "status", Items: []paletteWarningLook{}}, look.Warnings)
			assert.Equal(t, withColor(previewPalette("e1e0"), "canvas", "#111111"), fieldsOf(look, "light"))
			assert.Equal(t, previewPalette("e1d0"), fieldsOf(look, "dark"))
			assert.Zero(t, look.SectionInputs)
			assert.Empty(t, look.Navigations, "the page stays")
		})
	}
}

// A palette holding a value that is not a color is not sent: the region hides, since what it listed
// is no longer the palette's, until every color sent is one again. In Basic only the four rows are
// sent, so a value in one of the other 19 stops nothing.
func TestBrandPaletteJS_AValueThatIsNoColorIsNotSent(t *testing.T) {
	page := customPage()
	page.warnings = &paletteSaved{CountLine: "Every pair meets its minimum.", Items: []paletteAnswerItem{}}
	looks := runBrandPalette(t, page, load(),
		typeIn("palette-dark-brand", "#abc"), waitFor(5000), lookAt(),
		typeIn("palette-dark-brand", "#ABCDEF"), waitFor(300), lookAt())

	assert.Empty(t, looks[0].Requests)
	assert.True(t, looks[0].Warnings.Hidden)
	assert.Empty(t, looks[0].Warnings.Count)
	require.Len(t, looks[1].Requests, 1)
	assert.Equal(t, "#ABCDEF", looks[1].Requests[0].Body["palette-dark-brand"])

	looks = runBrandPalette(t, customPage(), load(),
		restoreValue("palette-light-focus", "nope"), typeIn("palette-light-ink", "#000000"), waitFor(300), lookAt())
	require.Len(t, looks[0].Requests, 1)
	assert.Equal(t, basicBody("auto", withColor(previewPalette("e1e0"), "ink", "#000000"), previewPalette("e1d0")), looks[0].Requests[0].Body)
}

// An advanced palette sends all 23 colors of each mode, and its answer, which works nothing out,
// leaves every field as typed: only the list is drawn.
func TestBrandPaletteJS_AnAdvancedPaletteSendsAll23AndKeepsThem(t *testing.T) {
	page := customPage()
	page.mode, page.storedMode = "advanced", "advanced"
	looks := runBrandPalette(t, page, load(),
		typeIn("palette-light-focus", "#ABCDEF"), waitFor(300), answer(0, 200, workedOut()), lookAt())

	look := looks[0]
	require.Len(t, look.Requests, 1)
	body := map[string]string{"paletteMode": "advanced", "appearance": "auto"}
	light := withColor(previewPalette("e1e0"), "focus", "#ABCDEF")
	for _, token := range brandTokens {
		body["palette-light-"+token] = light[token]
		body["palette-dark-"+token] = previewPalette("e1d0")[token]
	}
	assert.Equal(t, body, look.Requests[0].Body)
	assert.Equal(t, light, fieldsOf(look, "light"))
	assert.Equal(t, previewPalette("e1d0"), fieldsOf(look, "dark"))
	assert.Zero(t, look.SectionInputs)
	assert.Equal(t, workedOutList(), look.Warnings.Items)
}

// Going to Advanced fills the other 19 fields with the worked-out values (decision 7): an edit of the
// four not yet worked out is asked at once as a basic palette, and its answer fills them. After that,
// Advanced asks as an advanced palette. An edit of one of the 19 before that answer keeps what was
// typed, dropping the answer.
func TestBrandPaletteJS_GoingToAdvancedFillsTheWorkedOutValues(t *testing.T) {
	looks := runBrandPalette(t, customPage(), load(),
		typeIn("palette-light-canvas", "#101010"), pick("paletteMode", "advanced"), waitFor(0), lookAt(),
		answer(0, 200, workedOut()), lookAt(),
		typeIn("palette-dark-focus", "#ffcc00"), waitFor(300), lookAt())

	require.Len(t, looks[0].Requests, 1, "asked at once")
	assert.Equal(t, basicBody("auto", withColor(previewPalette("e1e0"), "canvas", "#101010"), previewPalette("e1d0")), looks[0].Requests[0].Body)
	assert.Equal(t, 0, rowsHidden(looks[1]))
	assert.Equal(t, "#a2e022", fieldsOf(looks[1], "light")["focus"], "the worked-out values")
	assert.Equal(t, "#a2d011", fieldsOf(looks[1], "dark")["danger"])
	assert.Equal(t, "#101010", fieldsOf(looks[1], "light")["canvas"])
	require.Len(t, looks[2].Requests, 2)
	assert.Equal(t, "advanced", looks[2].Requests[1].Body["paletteMode"])
	assert.Equal(t, "#ffcc00", looks[2].Requests[1].Body["palette-dark-focus"])

	looks = runBrandPalette(t, customPage(), load(),
		typeIn("palette-light-canvas", "#101010"), pick("paletteMode", "advanced"), waitFor(0),
		typeIn("palette-light-focus", "#123456"), answer(0, 200, workedOut()), lookAt(), waitFor(300), lookAt())

	assert.Equal(t, withColor(withColor(previewPalette("e1e0"), "canvas", "#101010"), "focus", "#123456"), fieldsOf(looks[0], "light"))
	assert.Equal(t, previewPalette("e1d0"), fieldsOf(looks[0], "dark"))
	require.Len(t, looks[1].Requests, 2)
	assert.Equal(t, "advanced", looks[1].Requests[1].Body["paletteMode"])
}

// A change that is not typed asks at once: the appearance, which decides the modes checked, the mode,
// Custom picked, and Copy colors from. Advanced, once a basic palette's answer filled the 19, asks as
// an advanced palette.
func TestBrandPaletteJS_AChoiceAsksAtOnce(t *testing.T) {
	looks := runBrandPalette(t, customPage(), load(),
		pick("appearance", "light"), waitFor(0), lookAt(), answer(0, 200, workedOut()),
		pick("paletteMode", "advanced"), waitFor(0), lookAt(),
		choose("paletteCopyFrom", "plum"), click("paletteCopy"), waitFor(0), lookAt())

	require.Len(t, looks[0].Requests, 1)
	assert.Equal(t, "light", looks[0].Requests[0].Body["appearance"])
	require.Len(t, looks[1].Requests, 2)
	assert.Equal(t, "advanced", looks[1].Requests[1].Body["paletteMode"])
	require.Len(t, looks[2].Requests, 3)
	assert.Equal(t, previewPlum.Light["note-ink"], looks[2].Requests[2].Body["palette-light-note-ink"])

	page := customPage()
	page.theme = "plum"
	looks = runBrandPalette(t, page, load(), pick("theme", "custom"), waitFor(0), lookAt())
	require.Len(t, looks[0].Requests, 1)
}

// A built-in theme asks nothing, whatever changes (#811 decision 3), and picking one drops the answer
// to a request sent while Custom was picked.
func TestBrandPaletteJS_ABuiltInThemeAsksNothing(t *testing.T) {
	page := customPage()
	page.theme = "plum"
	looks := runBrandPalette(t, page, load(),
		pick("appearance", "dark"), pick("theme", "blueberry"), choose("paletteCopyFrom", "plum"), click("paletteCopy"),
		waitFor(5000), lookAt())
	assert.Empty(t, looks[0].Requests)

	looks = runBrandPalette(t, customPage(), load(),
		typeIn("palette-light-canvas", "#111111"), waitFor(300), pick("theme", "plum"), answer(0, 200, workedOut()), lookAt())
	assert.Equal(t, withColor(previewPalette("e1e0"), "canvas", "#111111"), fieldsOf(looks[0], "light"))
	assert.Equal(t, listedNone, looks[0].Warnings)
}

// fullBody is the form a check of the 23 colors as the fields hold them sends: the mode advanced, the
// appearance, and every color of each mode, from light and dark.
func fullBody(appearance string, light, dark map[string]string) map[string]string {
	body := map[string]string{"paletteMode": "advanced", "appearance": appearance}
	for _, token := range brandTokens {
		body["palette-light-"+token] = light[token]
		body["palette-dark-"+token] = dark[token]
	}
	return body
}

// savedPage is customPage drawn with its saved brand's list, which describes the form as drawn.
func savedPage() palettePage {
	page := customPage()
	page.warnings = &paletteSaved{CountLine: "1 pair is below its minimum.",
		Items: []paletteAnswerItem{{Mode: "light", Foreground: "#e1e006", Background: "#e1e010", Text: "Light: Muted text on Soft brand background, 3.91:1. Minimum 4.5:1."}}}
	return page
}

// A saved brand's form, as its page draws it, is the one its list describes: neither the load nor a
// pageshow restoring nothing asks, so a saved basic palette's stored worked-out colors stay as stored.
func TestBrandPaletteJS_ASavedBrandsListIsKeptWhileTheFormIsTheOneItDescribes(t *testing.T) {
	looks := runBrandPalette(t, savedPage(), load(), waitFor(1000), previewStep{Do: "pageshow"}, waitFor(1000), lookAt())

	assert.Empty(t, looks[0].Requests)
	assert.Len(t, looks[0].Warnings.Items, 1, "the saved list, as the page drew it")
	assert.Equal(t, previewPalette("e1e0"), fieldsOf(looks[0], "light"))
}

// A refused custom form, whose page draws no list, is checked at once on load, with no edit. A basic
// palette's other 19 may be worked out from four colors edited since, as when the check could not be
// reached before the save, and its save works them out again from the four, so the four are sent as a
// basic palette and the answer fills the other 19: the list is the one the save answers.
func TestBrandPaletteJS_ARefusedFormIsCheckedOnLoad(t *testing.T) {
	page := customPage()
	page.light["ink"] = "#777777"
	page.light["ink-muted"] = "#605e5a"
	looks := runBrandPalette(t, page, load(), waitFor(0), lookAt(), answer(0, 200, workedOut()), lookAt())

	require.Len(t, looks[0].Requests, 1)
	assert.Equal(t, basicBody("auto", withColor(previewPalette("e1e0"), "ink", "#777777"), previewPalette("e1d0")),
		looks[0].Requests[0].Body)
	light := previewPalette("a2e0")
	for _, token := range basicRowTokens {
		light[token] = page.light[token]
	}
	assert.Equal(t, light, fieldsOf(looks[1], "light"), "the four kept, the stale 19 replaced by the answer's")
	assert.Equal(t, "#a2d006", fieldsOf(looks[1], "dark")["ink-muted"])
	labelled := "paletteWarningsCount"
	assert.Equal(t, paletteWarnings{Count: twoPairsSay, CountRole: "status", List: &labelled, Items: workedOutList()}, looks[1].Warnings)

	// A refused advanced palette is saved as its 23 fields hold them, so they are checked as they are,
	// and only the list is drawn.
	page = customPage()
	page.mode = "advanced"
	page.storedMode = "advanced"
	looks = runBrandPalette(t, page, load(), waitFor(0), lookAt(), answer(0, 200, workedOut()), lookAt())
	require.Len(t, looks[0].Requests, 1)
	assert.Equal(t, fullBody("auto", previewPalette("e1e0"), previewPalette("e1d0")), looks[0].Requests[0].Body)
	assert.Equal(t, previewPalette("e1e0"), fieldsOf(looks[1], "light"), "an advanced palette's colors are kept")
	assert.Zero(t, looks[1].SectionInputs)
	assert.Equal(t, twoPairsSay, looks[1].Warnings.Count)
}

// A refused basic form after an edit of its four colors the check could not answer: the save works
// the other 19 out from the four as edited, and so does the check on load, whatever the stale 19 hold.
func TestBrandPaletteJS_ARefusedFormAfterAnUncheckedEditIsWorkedOut(t *testing.T) {
	saved := savedPage()
	looks := runBrandPalette(t, saved, load(), typeIn("palette-light-ink", "#777777"), waitFor(1000),
		failRequest(0), lookAt())
	require.Len(t, looks[0].Requests, 1)
	assert.Equal(t, uncheckedSay, looks[0].Warnings.Count)
	assert.Equal(t, "#e1e006", fieldsOf(looks[0], "light")["ink-muted"], "the 19 still hold the saved palette's")

	// The save is refused for another field, and the page drawn again with the form as sent.
	refused := customPage()
	refused.light = fieldsOf(looks[0], "light")
	refused.dark = fieldsOf(looks[0], "dark")
	reply := workedOut()
	reply.Light["ink-muted"] = "#777777"
	looks = runBrandPalette(t, refused, load(), waitFor(0), lookAt(), answer(0, 200, reply), lookAt())
	require.Len(t, looks[0].Requests, 1)
	assert.Equal(t, basicBody("auto", withColor(previewPalette("e1e0"), "ink", "#777777"), previewPalette("e1d0")),
		looks[0].Requests[0].Body)
	assert.Equal(t, "#777777", fieldsOf(looks[1], "light")["ink-muted"])
}

// A browser restoring a saved brand's form to another appearance, as WebKit does on Back, before the
// script runs or before pageshow, leaves the saved list describing another form: it is asked at once
// for the appearance restored, and the answer replaces it.
func TestBrandPaletteJS_ARestoredAppearanceIsChecked(t *testing.T) {
	passing := workedOut()
	passing.CountLine = "Every pair meets its minimum."
	passing.Warnings = []paletteAnswerItem{}
	for name, steps := range map[string][]previewStep{
		"before the script runs": {restore("appearance", "dark"), load()},
		"before pageshow":        {load(), waitFor(1000), restore("appearance", "dark"), {Do: "pageshow"}},
	} {
		t.Run(name, func(t *testing.T) {
			run := slices.Concat(steps, []previewStep{waitFor(0), lookAt(), answer(0, 200, passing), lookAt()})
			looks := runBrandPalette(t, savedPage(), run...)

			require.Len(t, looks[0].Requests, 1)
			assert.Equal(t, fullBody("dark", previewPalette("e1e0"), previewPalette("e1d0")), looks[0].Requests[0].Body)
			assert.Equal(t, paletteWarnings{Count: "Every pair meets its minimum.", CountRole: "status", Items: []paletteWarningLook{}}, looks[1].Warnings)
			assert.Equal(t, previewPalette("e1e0"), fieldsOf(looks[1], "light"))
		})
	}
}

// A browser restoring a basic palette's four colors to ones the page was not drawn with, before the
// script runs or before pageshow, leaves the other 19 worked out from others, so the restored form is
// sent as a basic palette and its answer fills them.
func TestBrandPaletteJS_RestoredBasicColorsAreWorkedOutAgain(t *testing.T) {
	for name, steps := range map[string][]previewStep{
		"before the script runs": {restoreValue("palette-light-canvas", "#101010"), load()},
		"before pageshow": {load(), waitFor(1000), restoreValue("palette-light-canvas", "#101010"),
			{Do: "pageshow"}},
	} {
		t.Run(name, func(t *testing.T) {
			run := slices.Concat(steps, []previewStep{waitFor(0), answer(0, 200, workedOut()), lookAt()})
			looks := runBrandPalette(t, savedPage(), run...)

			require.Len(t, looks[0].Requests, 1)
			assert.Equal(t, basicBody("auto", withColor(previewPalette("e1e0"), "canvas", "#101010"), previewPalette("e1d0")), looks[0].Requests[0].Body)
			assert.Equal(t, "#a2e022", fieldsOf(looks[0], "light")["focus"])
			assert.Equal(t, "#101010", fieldsOf(looks[0], "light")["canvas"])
			assert.Equal(t, twoPairsSay, looks[0].Warnings.Count)
		})
	}

	// A stored advanced palette restored to Basic is worked out from its four as the save would.
	page := savedPage()
	page.mode = "advanced"
	page.storedMode = "advanced"
	looks := runBrandPalette(t, page, restore("paletteMode", "basic"), load(), waitFor(0), lookAt())
	require.Len(t, looks[0].Requests, 1)
	assert.Equal(t, "basic", looks[0].Requests[0].Body["paletteMode"])
}

// A pageshow restoring another form drops the answer to a request sent for the form before it, and
// asks for the restored one; an answer drawn makes its form the one the list describes, so a pageshow
// restoring nothing after it asks nothing.
func TestBrandPaletteJS_APageshowDropsTheAnswerForTheFormBeforeIt(t *testing.T) {
	looks := runBrandPalette(t, customPage(), load(), waitFor(0),
		restore("appearance", "light"), previewStep{Do: "pageshow"}, answer(0, 200, workedOut()), lookAt(),
		waitFor(0), answer(1, 200, workedOut()), previewStep{Do: "pageshow"}, waitFor(1000), lookAt())

	assert.Equal(t, listedNone, looks[0].Warnings, "the answer for Automatic is dropped")
	require.Len(t, looks[1].Requests, 2)
	assert.Equal(t, "light", looks[1].Requests[1].Body["appearance"])
	assert.Equal(t, twoPairsSay, looks[1].Warnings.Count)
}
