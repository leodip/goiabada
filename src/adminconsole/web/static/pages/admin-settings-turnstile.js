// admin-settings-turnstile.js is the Turnstile settings page's behaviour. Ticking the removal of the
// saved secret key disables the secret key's box, so a new secret key and a removal are never sent
// together, and shows the notice saying what the save will do; the box keeps what was typed, should
// the removal be unticked. The page draws no removal when no secret key is saved.

const secretKey = document.getElementById("turnstileSecretKey");
const clearSecretKey = document.getElementById("clearTurnstileSecretKey");

function showState() {
  const removing = clearSecretKey !== null && clearSecretKey.checked;
  secretKey.disabled = removing;
  const clearNotice = document.getElementById("clearTurnstileSecretKeyNotice");
  if (clearNotice) {
    clearNotice.hidden = !removing;
  }
}

if (clearSecretKey) {
  clearSecretKey.addEventListener("change", showState);
}
// pageshow comes after the browser restores the form, as on Back, which fires no change.
window.addEventListener("pageshow", showState);
showState();
