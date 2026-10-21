// admin-settings-email.js is the email settings page's behaviour. The server's sections show only
// while email is on: a save with it off clears them, so what they hold is not sent to be kept.
// Ticking the removal of the saved password disables the password box, so a new password and a
// removal are never sent together; the box keeps what was typed, should the removal be unticked.
// A saved password reaches only the host it was saved for, so editing the host away from that one
// needs the password again or its removal: the auth server refuses the save otherwise, and the
// page says so before the save is sent.

const smtpEnabled = document.getElementById("smtpEnabled");
const hostOrIP = document.getElementById("hostOrIP");
const password = document.getElementById("password");
const clearSmtpPassword = document.getElementById("clearSmtpPassword");

// normalizeHost is the host in the form the auth server compares it in: surrounding space trimmed,
// one pair of brackets taken off an IPv6 literal, and without regard to case.
function normalizeHost(host) {
  host = host.trim();
  if (host.length >= 2 && host.charAt(0) === "[" && host.charAt(host.length - 1) === "]") {
    host = host.substring(1, host.length - 1);
  }
  return host.toLowerCase();
}

function showState() {
  const enabled = smtpEnabled.checked;
  document.querySelectorAll("[data-smtp-section]").forEach(function (section) {
    section.hidden = !enabled;
  });

  const removing = clearSmtpPassword !== null && clearSmtpPassword.checked;
  password.disabled = removing;
  const clearNotice = document.getElementById("clearSmtpPasswordNotice");
  if (clearNotice) {
    clearNotice.hidden = !removing;
  }

  const hasSmtpPassword = document.getElementById("hasSmtpPassword").value === "true";
  const hostChanged = normalizeHost(hostOrIP.value) !== normalizeHost(document.getElementById("savedHostOrIP").value);
  const answered = password.value !== "" || removing;
  document.getElementById("hostChangeWarning").hidden = !(hasSmtpPassword && enabled && hostChanged && !answered);
}

smtpEnabled.addEventListener("change", showState);
if (clearSmtpPassword) {
  clearSmtpPassword.addEventListener("change", showState);
}
hostOrIP.addEventListener("input", showState);
password.addEventListener("input", showState);
// pageshow comes after the browser restores the form, as on Back, which fires no change.
window.addEventListener("pageshow", showState);
showState();
