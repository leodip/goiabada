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
    return true;
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
    } else if (target.name === "paletteMode") {
      if (target.value === "advanced") {
        visitedAdvanced = true;
      }
      drawMode();
      drawColumns(true);
    }
  });

  section.addEventListener("input", function (event) {
    const target = event.target;
    if (!target || !target.hasAttribute) {
      return;
    }
    if (target.hasAttribute("data-palette-value")) {
      markField(target);
      endFresh();
    } else if (target.hasAttribute("data-palette-well")) {
      const field = document.getElementById(target.id.replace(/-well$/, ""));
      if (field) {
        field.value = target.value;
        markField(field);
        endFresh();
      }
    }
  });

  const copyRow = section.querySelector("[data-palette-copy]");
  const copyButton = document.getElementById("paletteCopy");
  const copyFrom = document.getElementById("paletteCopyFrom");
  const copyStatus = document.getElementById("paletteCopyStatus");
  if (copyButton && copyFrom) {
    copyButton.addEventListener("click", function () {
      if (fill(copyFrom.value) && copyStatus) {
        copyStatus.textContent = copyStatus.dataset.copied || "";
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
