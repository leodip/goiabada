// admin-settings-sessions.js is the session settings page's behaviour: under each duration field
// it shows the number of seconds typed as a duration a person reads, as the value changes.

function showDurations() {
  const form = document.querySelector("form[data-duration-invalid]");
  if (!form) {
    return;
  }
  form.querySelectorAll("[data-duration-for]").forEach(function (output) {
    const input = document.getElementById(output.dataset.durationFor);
    if (!input) {
      return;
    }
    const update = function () {
      output.textContent = describeSeconds(input.value, form.dataset);
    };
    input.addEventListener("input", debounce(update, 300));
    update();
  });
}

showDurations();
