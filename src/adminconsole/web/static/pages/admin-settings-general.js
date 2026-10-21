// admin-settings-general.js is the general settings page's behaviour. Email verification is offered
// only while registration is on, since it governs nothing otherwise, and its row is hidden rather
// than disabled, so the choice made before is kept and still sent. Each caution shows while what it
// warns about holds: registration that needs email while email isn't set up, which the form's
// data-smtp-enabled says, PKCE not required, and a legacy flow on.

const generalForm = document.querySelector("form[data-smtp-enabled]");

function showWarnings() {
  const registration = document.getElementById("selfRegistrationEnabled").checked;
  const verification = document.getElementById("selfRegistrationRequiresEmailVerification").checked;
  document.getElementById("emailVerificationRow").hidden = !registration;
  document.getElementById("selfRegistrationEmailWarning").hidden =
    !(registration && verification && generalForm.dataset.smtpEnabled !== "true");
  document.getElementById("pkceWarning").hidden = document.getElementById("pkceRequired").checked;
  document.getElementById("implicitFlowWarning").hidden = !document.getElementById("implicitFlowEnabled").checked;
  document.getElementById("ropcFlowWarning").hidden = !document.getElementById("ropcFlowEnabled").checked;
}

generalForm.addEventListener("change", showWarnings);
// pageshow comes after the browser restores the form, as on Back, which fires no change.
window.addEventListener("pageshow", showWarnings);
showWarnings();
