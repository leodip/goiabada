// admin-users-new.js is the new user page's behaviour: the password field is for the choice to set
// the password now, so it is disabled and emptied while the choice is to email the user a link,
// and shown again with the choice, on change and on pageshow, after the browser restores a choice.

const passwordField = document.getElementById("password");
const passwordRow = document.getElementById("passwordField");

function showPasswordChoice() {
  const emailed = document.getElementById("setPasswordTypeEmail");
  const byEmail = emailed !== null && emailed.checked;
  passwordRow.hidden = byEmail;
  passwordField.disabled = byEmail;
  if (byEmail) {
    passwordField.value = "";
  }
}

document.querySelectorAll("input[name=setPasswordType]").forEach(function (choice) {
  choice.addEventListener("change", showPasswordChoice);
});
window.addEventListener("pageshow", showPasswordChoice);
