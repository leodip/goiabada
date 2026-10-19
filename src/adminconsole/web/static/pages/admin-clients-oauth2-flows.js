// admin-clients-oauth2-flows.js is the client OAuth2 flows tab's behaviour. The PKCE choice shows
// only while the authorization code flow is on, and each choice's warning shows while what it warns
// about would hold, PKCE optional or a legacy flow on, whether chosen outright or through the
// global setting, whose current value the form carries in data-global-*.

const flowsForm = document.querySelector("form[data-global-pkce-required]");

function chosen(name) {
  const radio = flowsForm.querySelector("input[name=" + name + "]:checked");
  return radio ? radio.value : "global";
}

// holds says whether a three-way choice comes to on, its global value deciding for "global".
function holds(name, globalValue) {
  const value = chosen(name);
  return value === "on" || (value === "global" && globalValue === "true");
}

function showWarnings() {
  const authCode = document.getElementById("authCodeEnabled");
  const pkceSection = document.getElementById("pkceSection");
  const pkceWarning = document.getElementById("pkceWarning");
  pkceSection.hidden = !authCode.checked;
  if (pkceWarning) {
    pkceWarning.hidden = !authCode.checked || holds("pkceRequired", flowsForm.dataset.globalPkceRequired);
  }
  document.getElementById("implicitWarning").hidden = !holds("implicitGrantEnabled", flowsForm.dataset.globalImplicitEnabled);
  document.getElementById("ropcWarning").hidden = !holds("ropcEnabled", flowsForm.dataset.globalRopcEnabled);
}

flowsForm.addEventListener("change", showWarnings);
// pageshow comes after the browser restores the form, as on Back, which fires no change.
window.addEventListener("pageshow", showWarnings);
showWarnings();
