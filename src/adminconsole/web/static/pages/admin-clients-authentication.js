// admin-clients-authentication.js is the client authentication tab's behaviour. The secret shows
// only for a confidential client, and choosing confidential for a client with none generates one.
// Show and Hide reveal the secret, which is drawn hidden, and Generate asks the console for a new
// one, which the field then shows, saying so in the tab's status region, as it says a failure. A
// type the browser restores, as on Back, is shown as chosen. The save, which asks first about a
// change of type and about a new secret, is shell.js's.

const secretPanel = document.getElementById("confidentialClientPanel");
const secretField = document.getElementById("clientSecret");
const showButton = document.getElementById("showSecretBtn");
const generateButton = document.getElementById("generateSecretBtn");
const secretStatus = document.getElementById("secret-status");
const confidentialRadio = document.getElementById("confidentialClientRadio");
const showLabel = showButton.textContent;

function showSecret(show) {
  secretField.type = show ? "text" : "password";
  showButton.textContent = show ? showButton.dataset.hideLabel : showLabel;
}

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
  sendAjaxRequest({
    url: "/admin/clients/generate-new-secret",
    method: "GET",
    bodyData: null,
    statusRegion: secretStatus,
    finished: function () {
      generating = false;
      generateButton.disabled = false;
    },
    callback: function (result) {
      const hadSecret = secretField.value !== "";
      secretField.value = result.NewSecret;
      if (hadSecret) {
        showSecret(true);
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
showButton.addEventListener("click", function () {
  showSecret(secretField.type === "password");
});
generateButton.addEventListener("click", generateSecret);
