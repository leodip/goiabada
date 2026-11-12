package web

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
  const section = el("fieldset", hiddenIf({ class: "palette-editor", id: "brand-palette", "data-palette-stored-mode": request.storedMode || "" },
    request.theme !== "custom"), [
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
  return { doc: doc, win: win };
}

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
  return {
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

type paletteLook struct {
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

// palettePage is the editor the stand-in draws: the theme checked, "custom" for the Custom card, the
// appearance, the mode checked, the mode of the palette stored, whether the fields hold untouched
// theme colors, and each field's value, by mode and token.
type palettePage struct {
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
