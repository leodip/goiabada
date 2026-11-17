// admin-clients-authentication.js is the client authentication tab's behaviour. The secret shows
// only for a confidential client, and choosing confidential for a client with none generates one.
// Show and Hide reveal the secret, which is drawn hidden, through utils.js's passwordToggle, whose
// controller for the Show button, reached here by id, shows a generated secret. Generate asks the
// console for a new one, which the field then shows, saying so in the tab's status region, as it
// says a failure. A type the browser restores, as on Back, is shown as chosen. The save, which asks
// first about a change of type and about a new secret, is shell.js's; Save is disabled while a secret
// is on its way, so a save never sends the field before the secret it is waiting for.

const secretPanel = document.getElementById("confidentialClientPanel");
const secretField = document.getElementById("clientSecret");
const showButton = document.getElementById("showSecretBtn");
const generateButton = document.getElementById("generateSecretBtn");
const saveButton = document.getElementById("btnSave");
const secretStatus = document.getElementById("secret-status");
const confidentialRadio = document.getElementById("confidentialClientRadio");
const secretToggle = passwordToggle(showButton);

// One generation runs at a time, Generate disabled meanwhile, so neither a second press nor a page
// restored from the back/forward cache mid-generation asks for a second secret that would replace
// one already shown, and perhaps copied.
let generating = false;

function generateSecret() {
  if (generating) {
    return;
  }
  generating = true;
  generateButton.disabled = true;
  saveButton.disabled = true;
  sendAjaxRequest({
    url: "/admin/clients/generate-new-secret",
    method: "GET",
    bodyData: null,
    statusRegion: secretStatus,
    finished: function () {
      generating = false;
      generateButton.disabled = false;
      saveButton.disabled = false;
    },
    callback: function (result) {
      const hadSecret = secretField.value !== "";
      secretField.value = result.NewSecret;
      if (hadSecret) {
        secretToggle.show(true);
        showNotice(secretStatus, "positive", secretStatus.dataset.generated);
      }
    }
  });
}

function showType() {
  secretPanel.hidden = !confidentialRadio.checked;
  if (confidentialRadio.checked && secretField.value === "") {
    generateSecret();
  }
}

document.querySelectorAll("input[name=publicConfidential]").forEach(function (radio) {
  radio.addEventListener("change", showType);
});
// pageshow comes after the browser restores the form, as on Back, which fires no change.
window.addEventListener("pageshow", showType);
generateButton.addEventListener("click", generateSecret);
