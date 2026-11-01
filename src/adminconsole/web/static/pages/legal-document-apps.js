// legal-document-apps.js is a legal document's Applies to page's behaviour: the apps to tick show
// only while Selected apps is chosen. A save of All apps clears them, so they would mean nothing.

const selectedApps = document.getElementById("appliesToSelectedApps");
const appsSection = document.getElementById("appsSection");

function showApps() {
  appsSection.hidden = !selectedApps.checked;
}

document.querySelectorAll('input[name="appliesTo"]').forEach(function (choice) {
  choice.addEventListener("change", showApps);
});
// pageshow comes after the browser restores the form, as on Back, which fires no change.
window.addEventListener("pageshow", showApps);
showApps();
