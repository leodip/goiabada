// admin-settings-ui-theme.js is the theme settings page's behaviour: choosing a theme shows it on
// this page at once, before it is saved, the way the layouts draw a saved one.

function previewTheme(theme) {
  const root = document.documentElement;
  const scheme = document.querySelector('meta[name="color-scheme"]');
  if (theme === "light" || theme === "dark") {
    root.dataset.theme = theme;
  } else {
    delete root.dataset.theme;
  }
  if (scheme) {
    scheme.content = theme === "light" || theme === "dark" ? theme : "light dark";
  }
}

document.querySelectorAll('input[name="themeSelection"]').forEach(function (radio) {
  radio.addEventListener("change", function () {
    if (radio.checked) {
      previewTheme(radio.value);
    }
  });
});
