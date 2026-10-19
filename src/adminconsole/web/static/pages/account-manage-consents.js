// account-manage-consents.js is the consents page's behaviour: each Revoke button asks in the
// page's dialog, with its own sentence, data-confirm, and then revokes that consent. The button
// gives way to a tag saying the consent was revoked, which takes the focus the button had, and the
// page's status region says so, as it says a failure.

function revokeConsent(button, status) {
  sendAjaxRequest({
    url: "/account/manage-consents",
    method: "POST",
    bodyData: JSON.stringify({ consentId: Number(button.dataset.revokeConsent) }),
    statusRegion: status,
    callback: function (result) {
      if (!result.Success) {
        return;
      }
      const revoked = document.createElement("span");
      revoked.className = "tag";
      revoked.tabIndex = -1;
      revoked.textContent = status.dataset.revokedLabel;
      button.replaceWith(revoked);
      revoked.focus();
      showNotice(status, "positive", status.dataset.revoked);
    }
  });
}

const consentsStatus = document.getElementById("consents-status");
document.querySelectorAll("button[data-revoke-consent]").forEach(function (button) {
  button.addEventListener("click", function () {
    showModalDialog("revokeConsent", consentsStatus.dataset.confirmTitle, button.dataset.confirm, null, function () {
      revokeConsent(button, consentsStatus);
    });
  });
});
