// account-user-sessions.js is the sessions page's behaviour: each End session button asks in its
// dialog, data-dialog, with its own sentence, data-confirm, and then ends that session. The button
// gives way to a tag saying the session ended, which takes the focus the button had, and the page's
// status region says so, as it says a failure. Ending the session of the device in use signs out, posted rather than
// asked again by the confirmation page, since the dialog has already asked (#411).

function endSession(button, status) {
  sendAjaxRequest({
    url: "/account/sessions",
    method: "POST",
    bodyData: JSON.stringify({ userSessionId: Number(button.dataset.endSession) }),
    statusRegion: status,
    callback: function (result) {
      if (!result.Success) {
        return;
      }
      if (result.IsCurrentSession) {
        submitSignOut();
        return;
      }
      const ended = document.createElement("span");
      ended.className = "tag";
      ended.tabIndex = -1;
      ended.textContent = status.dataset.endedLabel;
      button.replaceWith(ended);
      ended.focus();
      showNotice(status, "positive", status.dataset.ended);
    }
  });
}

const sessionsStatus = document.getElementById("sessions-status");
document.querySelectorAll("button[data-end-session]").forEach(function (button) {
  button.addEventListener("click", function () {
    showModalDialog(button.dataset.dialog, sessionsStatus.dataset.confirmTitle, button.dataset.confirm, null, function () {
      endSession(button, sessionsStatus);
    });
  });
});
