// brand-preview.js draws the brand editor's preview (#811): a sample sign-in card in each mode,
// light and dark, restyled at once from the theme the form holds, before it is saved. The page
// hands it every listed theme's light and dark palette in the brand-palettes data block. Each
// sample is given its own mode's 23 color tokens, the panel shadow and color-scheme that mode has
// on a real page, set on the sample alone through the CSSOM, so the editor around it keeps the
// console's own brand and the page carries no style attribute. A form holding a theme the list
// lacks, as a refused form drawn again can, is previewed in the first listed theme, as its
// Appearance cards are drawn.
//
// The appearance decides which sample shows: Light and Dark their one sample, with the Light/Dark
// switch hidden, and Automatic, or a form holding no appearance it knows, the sample the switch
// names. One sentence beside the preview says which applies. The switch sits outside the form, so
// it is never submitted. The samples are drawn hidden, so neither shows in the console's own
// colors before this script has styled it.
//
// Each sample also takes the corners and the font family the form holds (#813), from what the page
// hands it for each in the brand-kit-styles data block, the values the auth server's stylesheet sets:
// a shape's two radius tokens and a family's --font-sans, which ui.css reads on the sample as :root
// reads them on a real page. Rounded and System UI, today's look, are handed nothing, so the sample
// keeps the console's own tokens, which are ui.css's; so does a value the page hands nothing for, as a
// refused form drawn again can hold.
//
// The sample draws the kit's files too (#813), as the form's slots hold them, each slot's asset id and
// URL in two hidden fields, which brand-assets.js fills as a file is uploaded and empties as it is
// removed, telling the page with an input event: the logo of each sample's mode above the app name,
// the dark logo in the dark one, or the logo while there is none, and the name hidden beside a logo
// while the switch hides it; the background image behind the card at the fit the form holds, as the
// page hands each fit's layout, over the canvas; and the uploaded font, declared in the page under the
// family its list names first, with the weights the page hands for two files, and none while another
// family is chosen or no regular file is there. Its list is set whatever the files, as the other
// families' are: without them it falls back to System UI, as the saved brand is drawn. The favicon has
// no place on a sign-in card: its field shows it.
//
// The three Appearance cards' swatches are redrawn in the chosen theme too, from the same
// palettes: each names the modes it shows, one SVG per mode in order, and each shape the token its
// fill or border is drawn from. The colors are set as attributes, as the server draws them. The
// theme cards' swatches each show their own theme and are left alone.
//
// A browser restoring the form, as on Back, fires no input, so all of it is drawn again on every
// pageshow.

const brandPalettes = JSON.parse(document.getElementById("brand-palettes").textContent);
const brandKitStyles = JSON.parse(document.getElementById("brand-kit-styles").textContent);

// The panel shadow ui.css gives each mode, which the token palettes do not carry.
const samplePanelShadows = {
  light: "0 1px 2px rgb(16 24 40 / 0.05), 0 1px 3px rgb(16 24 40 / 0.08)",
  dark: "0 1px 2px rgb(0 0 0 / 0.4)",
};

// chosenTheme answers the palettes of the theme the form holds, or of the first listed theme.
function chosenTheme() {
  const checked = document.querySelector('input[name="theme"]:checked');
  const key = checked ? checked.value : "";
  return brandPalettes.find(function (theme) { return theme.key === key; }) || brandPalettes[0];
}

// chosenAppearance answers the appearance the form holds, auto when it holds none: a refused
// form drawn again with an appearance it does not offer checks no card.
function chosenAppearance() {
  const checked = document.querySelector('input[name="appearance"]:checked');
  return checked ? checked.value : "auto";
}

// handed answers what the page hands for key in styles, or undefined when it hands nothing, a key
// every object answers, such as constructor, included.
function handed(styles, key) {
  return styles && Object.prototype.hasOwnProperty.call(styles, key) ? styles[key] : undefined;
}

// chosenRadii answers the radii of the corner shape the form holds, undefined for one that sets none.
function chosenRadii() {
  const checked = document.querySelector('input[name="corners"]:checked');
  return handed(brandKitStyles.corners, checked ? checked.value : "");
}

// chosenFontStack answers the font-family list of the family the form holds, undefined for one that
// sets none.
function chosenFontStack() {
  const select = document.getElementById("font");
  return handed(brandKitStyles.fonts, select ? select.value : "");
}

// slotUrl answers the URL of the file the form's slot holds, or "" for an empty slot: one whose id
// field is empty holds nothing, whatever its URL field holds.
function slotUrl(slot) {
  const id = document.querySelector('input[type="hidden"][name="' + slot + '"]');
  const url = document.querySelector('input[type="hidden"][name="' + slot + 'Url"]');
  return id && url && id.value ? url.value : "";
}

// chosenBackground answers the layout of the fit the form holds, or cover's for a fit the page hands
// nothing for, as the auth server lays it out.
function chosenBackground() {
  const checked = document.querySelector('input[name="backgroundFit"]:checked');
  return handed(brandKitStyles.backgrounds, checked ? checked.value : "") || handed(brandKitStyles.backgrounds, "cover") || {};
}

// cssUrl is url() naming address, as a CSS string.
function cssUrl(address) {
  return "url(" + JSON.stringify(address) + ")";
}

// The uploaded font's faces the page has declared, and the files they were declared from.
let declaredFaces = [];
let declaredFiles = "";

// declareUploadedFont declares the uploaded font's faces from its regular and bold files, or none for
// no regular file, replacing the ones declared before. A browser loads a face once text asks for its
// family, so a face declared costs nothing until the sample draws it.
function declareUploadedFont(regular, bold) {
  const files = regular ? regular + "\n" + bold : "";
  if (files === declaredFiles || !document.fonts || typeof FontFace !== "function") {
    return;
  }
  for (const face of declaredFaces) {
    document.fonts.delete(face);
  }
  declaredFaces = [];
  declaredFiles = files;
  if (!regular) {
    return;
  }
  const family = brandKitStyles.uploadedFamily;
  const weights = brandKitStyles.fontWeights || {};
  const face = function (url, weight) {
    const descriptors = { display: "swap" };
    if (weight) {
      descriptors.weight = weight;
    }
    return new FontFace(family, cssUrl(url) + ' format("woff2")', descriptors);
  };
  declaredFaces = bold ? [face(regular, weights.regular), face(bold, weights.bold)] : [face(regular, "")];
  for (const declared of declaredFaces) {
    document.fonts.add(declared);
  }
}

// drawLogo puts the logo at url in a sample's logo box above the app name, or empties the box for
// none, and hides the name beside a logo while the switch hides it.
function drawLogo(sample, url, hideName) {
  const box = sample.querySelector(".auth-logo");
  if (box) {
    let image = box.querySelector("img");
    if (url) {
      if (!image) {
        image = document.createElement("img");
        image.setAttribute("alt", "");
        box.appendChild(image);
      }
      if (image.getAttribute("src") !== url) {
        image.setAttribute("src", url);
      }
    } else if (image) {
      image.remove();
    }
    box.hidden = !url;
  }
  const name = sample.querySelector(".auth-brand");
  if (name) {
    name.hidden = Boolean(url) && hideName;
  }
}

// setOrRemove sets a property on a sample's style, or takes it off when there is no value.
function setOrRemove(style, property, value) {
  if (typeof value === "string" && value !== "") {
    style.setProperty(property, value);
  } else {
    style.removeProperty(property);
  }
}

// previewMode answers the mode the switch is on, light unless it is on dark.
function previewMode() {
  const checked = document.querySelector('input[name="brandPreviewMode"]:checked');
  return checked && checked.value === "dark" ? "dark" : "light";
}

// drawSwatch gives each shape of one swatch SVG its token's color in palette.
function drawSwatch(svg, palette) {
  for (const shape of svg.querySelectorAll("[data-fill]")) {
    const fill = palette[shape.dataset.fill];
    if (fill !== undefined) {
      shape.setAttribute("fill", fill);
    }
  }
  for (const shape of svg.querySelectorAll("[data-stroke]")) {
    const stroke = palette[shape.dataset.stroke];
    if (stroke !== undefined) {
      shape.setAttribute("stroke", stroke);
    }
  }
}

function drawAppearanceSwatches(theme) {
  for (const swatch of document.querySelectorAll("[data-appearance-swatch]")) {
    const modes = swatch.dataset.appearanceSwatch.split(" ");
    const svgs = swatch.querySelectorAll("svg");
    for (let i = 0; i < svgs.length && i < modes.length; i++) {
      drawSwatch(svgs[i], theme[modes[i] === "dark" ? "dark" : "light"] || {});
    }
  }
}

function drawPreview() {
  const theme = chosenTheme();
  if (!theme) {
    return;
  }
  const appearance = chosenAppearance();
  const mode = appearance === "auto" ? previewMode() : appearance;
  const radii = chosenRadii() || {};
  const fontStack = chosenFontStack();
  const font = document.getElementById("font");
  declareUploadedFont(font && font.value === "uploaded" ? slotUrl("regularFont") : "", slotUrl("boldFont"));
  const logo = slotUrl("logo");
  const darkLogo = slotUrl("darkLogo") || logo;
  const switchOn = document.getElementById("hideAppName");
  const hideName = Boolean(switchOn && switchOn.checked);
  const background = slotUrl("background");
  const layout = background ? chosenBackground() : {};
  for (const sample of document.querySelectorAll("[data-brand-sample]")) {
    const sampleMode = sample.dataset.brandSample === "dark" ? "dark" : "light";
    const palette = theme[sampleMode] || {};
    for (const token of Object.keys(palette)) {
      sample.style.setProperty("--color-" + token, palette[token]);
    }
    sample.style.setProperty("--shadow-panel", samplePanelShadows[sampleMode]);
    sample.style.setProperty("color-scheme", sampleMode);
    setOrRemove(sample.style, "--radius-control", radii.control);
    setOrRemove(sample.style, "--radius-panel", radii.panel);
    setOrRemove(sample.style, "--font-sans", fontStack);
    setOrRemove(sample.style, "background-image", background ? cssUrl(background) : undefined);
    setOrRemove(sample.style, "background-size", layout.size);
    setOrRemove(sample.style, "background-position", layout.position);
    setOrRemove(sample.style, "background-repeat", layout.repeat);
    drawLogo(sample, sampleMode === "dark" ? darkLogo : logo, hideName);
    sample.hidden = sampleMode !== mode;
  }
  const modeSwitch = document.querySelector(".brand-preview-switch");
  if (modeSwitch) {
    modeSwitch.hidden = appearance !== "auto";
  }
  for (const note of document.querySelectorAll("[data-brand-preview-note]")) {
    note.hidden = note.dataset.brandPreviewNote !== appearance;
  }
  drawAppearanceSwatches(theme);
}

drawPreview();
document.addEventListener("input", drawPreview);
window.addEventListener("pageshow", drawPreview);
