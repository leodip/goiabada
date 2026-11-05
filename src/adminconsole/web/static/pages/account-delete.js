// account-delete.js is the Delete account page's choice of second factor: its button swaps the
// authentication code field for the recovery code field and back. The field not shown is disabled
// as well as hidden, so the form posts only the code the user chose, which is how the console
// tells the auth server which one it is (#783 decision 2). The button is drawn hidden and shown
// here, so without this script the page offers the authentication code alone.

document.querySelectorAll("button[data-second-factor-toggle]").forEach(function (button) {
  const otpField = document.getElementById("otp-field");
  const recoveryField = document.getElementById("recovery-code-field");
  if (!otpField || !recoveryField) {
    return;
  }
  const otp = document.getElementById("otp");
  const recoveryCode = document.getElementById("recoveryCode");

  function show(useRecoveryCode) {
    otpField.hidden = useRecoveryCode;
    otp.disabled = useRecoveryCode;
    recoveryField.hidden = !useRecoveryCode;
    recoveryCode.disabled = !useRecoveryCode;
    button.textContent = useRecoveryCode ? button.dataset.useAuthenticator : button.dataset.useRecoveryCode;
  }

  button.addEventListener("click", function () {
    const useRecoveryCode = recoveryField.hidden;
    show(useRecoveryCode);
    (useRecoveryCode ? recoveryCode : otp).focus();
  });
  // pageshow comes after the browser restores the form, as on Back, which fires no change: the
  // fields are shown again as the restored inputs say.
  window.addEventListener("pageshow", function () {
    show(otp.disabled);
  });
  button.hidden = false;
});
