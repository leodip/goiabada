// brand-preview.js draws the brand editor's preview (#811): a sample sign-in card in each mode,
// light and dark, restyled at once from the theme the form holds, before it is saved. The page
// hands it every listed theme's light and dark palette in the brand-palettes data block. Each
// sample is given its own mode's 23 color tokens, the panel shadow and color-scheme that mode has
// on a real page, set on the sample alone through the CSSOM, so the editor around it keeps the
// console's own brand and the page carries no style attribute. A form holding a theme the list
// lacks, as a refused form drawn again can, is previewed in the first listed theme, as its
// Appearance cards are drawn.
//
// The Light/Dark switch shows one sample at a time; it sits outside the form, so it is never
// submitted. The samples are drawn hidden, so neither shows in the console's own colors before
// this script has styled it. A browser restoring the form, as on Back, fires no input, so the
// preview is drawn again on every pageshow.

const brandPalettes = JSON.parse(document.getElementById("brand-palettes").textContent);

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

// previewMode answers the mode the switch is on, light unless it is on dark.
function previewMode() {
  const checked = document.querySelector('input[name="brandPreviewMode"]:checked');
  return checked && checked.value === "dark" ? "dark" : "light";
}

function drawPreview() {
  const theme = chosenTheme();
  if (!theme) {
    return;
  }
  const mode = previewMode();
  for (const sample of document.querySelectorAll("[data-brand-sample]")) {
    const sampleMode = sample.dataset.brandSample === "dark" ? "dark" : "light";
    const palette = theme[sampleMode] || {};
    for (const token of Object.keys(palette)) {
      sample.style.setProperty("--color-" + token, palette[token]);
    }
    sample.style.setProperty("--shadow-panel", samplePanelShadows[sampleMode]);
    sample.style.setProperty("color-scheme", sampleMode);
    sample.hidden = sampleMode !== mode;
  }
}

drawPreview();
document.addEventListener("input", drawPreview);
window.addEventListener("pageshow", drawPreview);
