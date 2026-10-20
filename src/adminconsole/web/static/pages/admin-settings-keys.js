// admin-settings-keys.js is the signing keys page's behaviour: a key's PEM, JWK or ASN.1 DER button
// shows that encoding of its public key in #publicKeyDialog, read from the page's signing-keys data
// block, where the dialog's Copy button copies it. A JWK is shown indented, as JSON. Each text is
// set as text, so no key value reaches an HTML parser.

const signingKeys = JSON.parse(document.getElementById("signing-keys").textContent);
const publicKeyDialog = document.getElementById("publicKeyDialog");

// encoding answers the text of key in format, "pem", "jwk" or "der".
function encoding(key, format) {
  if (format === "pem") {
    return key.PublicKeyPEM;
  }
  if (format === "jwk") {
    try {
      return JSON.stringify(JSON.parse(key.PublicKeyJWK), null, 2);
    } catch (err) {
      return key.PublicKeyJWK;
    }
  }
  return key.PublicKeyASN1DER;
}

document.addEventListener("click", function (event) {
  const button = event.target.closest("button[data-public-key]");
  if (!button) {
    return;
  }
  const key = signingKeys.find(function (k) {
    return k.KeyIdentifier === button.dataset.publicKey;
  });
  if (!key) {
    return;
  }
  const format = button.dataset.format;
  document.getElementById("publicKeyDialogTitle").textContent =
    publicKeyDialog.dataset["title" + format.charAt(0).toUpperCase() + format.slice(1)];
  document.getElementById("publicKeyDialogKeyId").textContent = key.KeyIdentifier;
  const content = document.getElementById("publicKeyContent");
  content.textContent = encoding(key, format);
  content.scrollTop = 0;
  publicKeyDialog.showModal();
});
