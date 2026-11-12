// brand-palette.js keeps the brand editor's Colors section in step with the form (#815 decisions 7
// and 8), which the page draws for the form as it was sent or stored, so all of it works with
// scripts off except the color wells and Copy colors from, which it shows.
//
// The section shows while the Custom theme card is picked, and hides when a built-in theme is,
// keeping what it holds. The first time Custom is picked for a brand with no palette, while the
// fields still hold the colors the page was drawn with (the paletteFresh field says so), they take
// the colors of the built-in theme picked before it. Any edit, and Copy colors from, end that.
//
// Basic shows the four rows a basic palette is entered with, Advanced all 23 with their group names
// and token names; going back to Basic, over a palette stored in Advanced or after Advanced was shown
// here, shows the note saying the others are worked out at the save.
//
// A text field holding a value that is not # and six hexadecimal digits is marked invalid, its
// message shown and named in its aria-describedby; one holding a color sets its well, in lower case. A
// color picked in a well is written in its field. The columns follow the appearance: Light hides the
// Dark column and Dark the Light one, each with a line saying its colors are kept and not used. A
// column a field of a shown row holds a value that is not a color in stays shown, with a line saying
// its colors must be valid, and hides again at the next appearance change once every field in it is a
// color; picking Advanced only adds the column a row it shows needs. Copy colors from writes a
// built-in theme's colors, from the brand-palettes data block, in every field of both modes and says
// so in its status line.
//
// A browser restoring the form, as on Back, fires no input, so all of it is drawn again on pageshow.
//
// The live check (#815 decision 6): while Custom is picked, the entered palette is posted to the
// console's check route, the section's data-palette-check-url, which works it out and checks it with
// the code the save uses and answers the 23 colors of each mode and the failing pairs of the modes
// the appearance draws. A typed edit waits for a pause in editing; a choice (the appearance, Basic or
// Advanced, Custom picked, Copy colors from) asks at once. Every change drops the answer to any
// request before it, so only the answer to the latest request is drawn. A basic palette sends its
// four colors of each mode, an advanced one all 23, and a palette holding a value that is not a color
// among them is not sent: the region of warnings hides until it is one again. A basic palette's answer
// is written in the fields of the other 19 rows, and the page told with an input event on the section,
// so the preview draws them and going to Advanced shows them; going to Advanced over an edit of the
// four not yet worked out asks for it at once as a basic palette. The answer's pairs replace the list
// under the count line, which is the part announced. When the route cannot be reached, the network
// failing or the sign-in having ended, or it answers anything else, the count line says the colors
// could not be checked and are checked when the brand is saved, and the list is emptied; the fields,
// which the preview draws, keep what was entered, and the page stays, its form unsaved, for the save
// to check them. A built-in theme asks nothing.

(function () {
  "use strict";

  const section = document.getElementById("brand-palette");
  const palettesBlock = document.getElementById("brand-palettes");
  if (!section || !palettesBlock) {
    return;
  }
  const palettes = JSON.parse(palettesBlock.textContent);
  const modes = ["light", "dark"];
  const colorPattern = /^#[0-9a-fA-F]{6}$/;
  const freshField = section.querySelector('input[name="paletteFresh"]');

  // The built-in theme checked before Custom, and whether Advanced was shown since the page loaded.
  let previousTheme = "";
  let visitedAdvanced = false;

  // The live check: the route, the pause a typed edit waits for, the timer of the request to send,
  // the number of the latest change, whose answer alone is drawn, and whether the four colors were
  // changed in Basic since a basic palette's answer last filled the other 19.
  const checkUrl = section.dataset.paletteCheckUrl || "";
  const checkPause = 300;
  const region = document.getElementById("palette-warnings");
  const countLine = document.getElementById("paletteWarningsCount");
  const svgNamespace = "http://www.w3.org/2000/svg";
  let checkTimer = null;
  let latestChange = 0;
  let fillDue = false;

  function checkedValue(name) {
    const checked = document.querySelector('input[name="' + name + '"]:checked');
    return checked ? checked.value : "";
  }

  function textFields() {
    return section.querySelectorAll("input[data-palette-value]");
  }

  function isColor(value) {
    return colorPattern.test(value.trim());
  }

  function isFresh() {
    return Boolean(freshField && freshField.value === "true");
  }

  function endFresh() {
    if (freshField) {
      freshField.value = "";
    }
  }

  // describedBy adds token to, or takes it from, a field's aria-describedby.
  function describedBy(field, token, on) {
    const tokens = (field.getAttribute("aria-describedby") || "").split(/\s+/).filter(function (t) {
      return t && t !== token;
    });
    if (on) {
      tokens.push(token);
    }
    if (tokens.length > 0) {
      field.setAttribute("aria-describedby", tokens.join(" "));
    } else {
      field.removeAttribute("aria-describedby");
    }
  }

  // markField marks a text field invalid while its value is not a color, and sets its well to it while
  // it is one.
  function markField(field) {
    const valid = isColor(field.value);
    const message = document.getElementById(field.id + "-error");
    if (valid) {
      field.removeAttribute("aria-invalid");
      const well = document.getElementById(field.id + "-well");
      if (well) {
        well.value = field.value.trim().toLowerCase();
      }
    } else {
      field.setAttribute("aria-invalid", "true");
    }
    if (message) {
      message.hidden = valid;
    }
    describedBy(field, field.id + "-error", !valid);
  }

  function basicMode() {
    return checkedValue("paletteMode") !== "advanced";
  }

  // drawnModes answers whether the appearance draws each mode: Light its light one, Dark its dark one,
  // and Automatic, or none the script knows, both.
  function drawnModes() {
    const appearance = checkedValue("appearance");
    return { light: appearance !== "dark", dark: appearance !== "light" };
  }

  // holdsNoColor reports whether a field of mode in a row the mode shows holds a value that is not a
  // color.
  function holdsNoColor(mode) {
    for (const field of textFields()) {
      const row = field.closest("[data-palette-row]");
      const cell = field.closest("[data-palette-column]");
      if (cell && cell.dataset.paletteColumn === mode && !(row && row.hidden) && !isColor(field.value)) {
        return true;
      }
    }
    return false;
  }

  // drawColumns shows each column the appearance draws or that holds a value that is not a color,
  // and hides the others, or with keep, hides none that shows.
  function drawColumns(keep) {
    const drawn = drawnModes();
    for (const mode of modes) {
      const head = document.getElementById("palette-head-" + mode);
      const shownNow = Boolean(head && !head.hidden);
      const shown = drawn[mode] || holdsNoColor(mode) || (keep && shownNow);
      for (const cell of section.querySelectorAll('[data-palette-column="' + mode + '"]')) {
        cell.hidden = !shown;
      }
      for (const note of section.querySelectorAll('[data-palette-note="unused-' + mode + '"]')) {
        note.hidden = shown;
      }
      for (const note of section.querySelectorAll('[data-palette-note="invalid-' + mode + '"]')) {
        note.hidden = !shown || drawn[mode];
      }
    }
  }

  // drawMode shows the rows, group names and token names of the mode the form holds, and the note on
  // going back to Basic.
  function drawMode() {
    const basic = basicMode();
    for (const element of section.querySelectorAll("[data-palette-advanced]")) {
      element.hidden = basic;
    }
    const storedAdvanced = section.dataset.paletteStoredMode === "advanced";
    for (const note of section.querySelectorAll("[data-palette-basic-note]")) {
      note.hidden = !(basic && (storedAdvanced || visitedAdvanced));
    }
  }

  function drawSection() {
    section.hidden = checkedValue("theme") !== "custom";
  }

  // fill writes a built-in theme's colors in every field of both modes.
  function fill(key) {
    const theme = palettes.find(function (candidate) { return candidate.key === key; });
    if (!theme) {
      return false;
    }
    for (const mode of modes) {
      const colors = theme[mode] || {};
      for (const token of Object.keys(colors)) {
        const field = document.getElementById("palette-" + mode + "-" + token);
        if (field) {
          field.value = colors[token];
          markField(field);
        }
      }
    }
    endFresh();
    tellPage();
    return true;
  }

  // tellPage tells the page the script wrote fields, as an edit would, so the preview draws them.
  function tellPage() {
    section.dispatchEvent(new Event("input", { bubbles: true }));
  }

  // rowTokens answers the tokens of the rows a check sends: the four Basic shows, or all 23.
  function rowTokens(basic) {
    const tokens = [];
    for (const row of section.querySelectorAll("[data-palette-row]")) {
      if (!basic || row.hasAttribute("data-palette-basic")) {
        tokens.push(row.dataset.paletteRow);
      }
    }
    return tokens;
  }

  // fillWith fills a swatch's shape with color, in lower case, when it is one, and with nothing else.
  function fillWith(shape, color) {
    if (typeof color === "string" && isColor(color)) {
      shape.setAttribute("fill", color.trim().toLowerCase());
    }
  }

  // showWarnings draws the region: hidden with nothing in it for no line, else the line, and a list
  // of items, each a pair's sentence beside a swatch of it, the foreground drawn on the background,
  // each drawn only in a color.
  function showWarnings(line, items) {
    if (!region || !countLine) {
      return;
    }
    region.hidden = line === null;
    countLine.textContent = line || "";
    let list = region.querySelector("ul.palette-warning-list");
    if (!items || items.length === 0) {
      if (list) {
        list.remove();
      }
      return;
    }
    if (!list) {
      list = document.createElement("ul");
      list.setAttribute("class", "palette-warning-list");
      list.setAttribute("aria-labelledby", countLine.id);
      region.appendChild(list);
    }
    list.replaceChildren(...items.map(function (item) {
      const entry = document.createElement("li");
      entry.setAttribute("class", "palette-warning");
      entry.setAttribute("data-palette-warning-mode", String(item.mode));
      const swatch = document.createElementNS(svgNamespace, "svg");
      swatch.setAttribute("class", "palette-warning-swatch");
      swatch.setAttribute("viewBox", "0 0 40 24");
      swatch.setAttribute("preserveAspectRatio", "none");
      swatch.setAttribute("aria-hidden", "true");
      swatch.setAttribute("focusable", "false");
      const background = document.createElementNS(svgNamespace, "rect");
      background.setAttribute("width", "40");
      background.setAttribute("height", "24");
      fillWith(background, item.background);
      const foreground = document.createElementNS(svgNamespace, "rect");
      foreground.setAttribute("x", "9");
      foreground.setAttribute("y", "9");
      foreground.setAttribute("width", "22");
      foreground.setAttribute("height", "6");
      foreground.setAttribute("rx", "1");
      fillWith(foreground, item.foreground);
      swatch.appendChild(background);
      swatch.appendChild(foreground);
      const text = document.createElement("span");
      text.textContent = String(item.text);
      entry.appendChild(swatch);
      entry.appendChild(text);
      return entry;
    }));
  }

  // drawAnswer draws the answer to a check: for a basic palette, the worked-out colors in the fields
  // of the other 19 rows, telling the page; then the list.
  function drawAnswer(answer, basic) {
    if (basic) {
      const four = rowTokens(true);
      for (const mode of modes) {
        for (const token of Object.keys(answer[mode])) {
          const field = document.getElementById("palette-" + mode + "-" + token);
          if (field && four.indexOf(token) < 0 && isColor(String(answer[mode][token]))) {
            field.value = String(answer[mode][token]);
            markField(field);
          }
        }
      }
      fillDue = false;
      tellPage();
    }
    showWarnings(String(answer.countLine || ""), Array.isArray(answer.warnings) ? answer.warnings : []);
  }

  // check sends the palette as the form holds it, unless a color it sends is not one, and draws the
  // answer if no change came after it.
  function check(change) {
    const basic = fillDue || basicMode();
    const body = new URLSearchParams();
    body.append("paletteMode", basic ? "basic" : "advanced");
    body.append("appearance", checkedValue("appearance"));
    for (const mode of modes) {
      for (const token of rowTokens(basic)) {
        const field = document.getElementById("palette-" + mode + "-" + token);
        if (!field || !isColor(field.value)) {
          showWarnings(null, []);
          return;
        }
        body.append(field.name, field.value.trim());
      }
    }
    fetch(withPageLanguage(checkUrl), { method: "POST", body: body, headers: scriptRequestHeaders() })
      .then(function (response) {
        return response.json().then(function (data) {
          // A sign-in that has ended leaves the colors unchecked like any failure: going to the
          // session-ended route would lose the form being edited, whose save then signs in again.
          const answered = response.ok && data && typeof data.light === "object" && data.light &&
            typeof data.dark === "object" && data.dark;
          if (isSessionEnded(data) || !answered) {
            throw new Error("the colors were not checked");
          }
          return data;
        });
      })
      .then(function (answer) {
        if (change === latestChange) {
          drawAnswer(answer, basic);
        }
      })
      .catch(function () {
        if (change === latestChange && region && countLine) {
          showWarnings(region.dataset.unchecked || "", []);
        }
      });
  }

  // ask drops the answer to every earlier request and, while Custom is picked, sends the palette
  // after delay, a pause for a typed edit and none for a choice. An edit in Basic leaves the other 19
  // to be worked out again.
  function ask(delay) {
    latestChange++;
    clearTimeout(checkTimer);
    checkTimer = null;
    if (!checkUrl || checkedValue("theme") !== "custom") {
      return;
    }
    if (basicMode()) {
      fillDue = true;
    }
    const change = latestChange;
    checkTimer = setTimeout(function () {
      checkTimer = null;
      check(change);
    }, delay);
  }

  function drawAll() {
    for (const field of textFields()) {
      markField(field);
    }
    drawSection();
    drawMode();
    drawColumns(false);
  }

  function themePicked() {
    const theme = checkedValue("theme");
    if (theme !== "custom") {
      previousTheme = theme;
    } else if (isFresh() && previousTheme) {
      fill(previousTheme);
    }
    drawSection();
    ask(0);
  }

  document.addEventListener("change", function (event) {
    const target = event.target;
    if (!target || target.type !== "radio") {
      return;
    }
    if (target.name === "theme") {
      themePicked();
    } else if (target.name === "appearance") {
      drawColumns(false);
      ask(0);
    } else if (target.name === "paletteMode") {
      if (target.value === "advanced") {
        visitedAdvanced = true;
      }
      drawMode();
      drawColumns(true);
      ask(0);
    }
  });

  // edited follows a field's edit: one of the 19 rows edited in Advanced takes them in hand, so they
  // are no longer worked out; then the palette is asked after the pause.
  function edited(field) {
    markField(field);
    endFresh();
    if (!basicMode() && rowTokens(true).indexOf(field.id.replace(/^palette-(light|dark)-/, "")) < 0) {
      fillDue = false;
    }
    ask(checkPause);
  }

  section.addEventListener("input", function (event) {
    const target = event.target;
    if (!target || !target.hasAttribute) {
      return;
    }
    if (target.hasAttribute("data-palette-value")) {
      edited(target);
    } else if (target.hasAttribute("data-palette-well")) {
      const field = document.getElementById(target.id.replace(/-well$/, ""));
      if (field) {
        field.value = target.value;
        edited(field);
      }
    }
  });

  const copyRow = section.querySelector("[data-palette-copy]");
  const copyButton = document.getElementById("paletteCopy");
  const copyFrom = document.getElementById("paletteCopyFrom");
  const copyStatus = document.getElementById("paletteCopyStatus");
  if (copyButton && copyFrom) {
    copyButton.addEventListener("click", function () {
      if (fill(copyFrom.value)) {
        if (copyStatus) {
          copyStatus.textContent = copyStatus.dataset.copied || "";
        }
        ask(0);
      }
    });
  }

  if (copyRow) {
    copyRow.hidden = false;
  }
  for (const well of section.querySelectorAll("[data-palette-well]")) {
    well.hidden = false;
  }
  const checkedTheme = checkedValue("theme");
  if (checkedTheme !== "custom") {
    previousTheme = checkedTheme;
  }
  drawAll();
  window.addEventListener("pageshow", drawAll);
})();
