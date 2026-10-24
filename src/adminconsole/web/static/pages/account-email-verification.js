// account-email-verification.js is the email verification page's behaviour: its Send code button
// asks the console to email a code, and the answer, or why it failed, is said in the page's status
// region, where the button's data-sent and data-wait give the sentences. data-wait names the time
// to wait as {wait}, which only the answer knows, and which is written as a duration in the page's
// language, such as "4 minutes, 20 seconds", by utils.js's formatDuration, counted in hours down to
// seconds, never days.

function sendVerificationCode(button) {
  const status = document.getElementById("verification-status");
  const code = document.getElementById("verificationCode");
  sendAjaxRequest({
    url: "/account/email-send-verification",
    method: "POST",
    bodyData: JSON.stringify({}),
    statusRegion: status,
    callback: function (result) {
      if (result.EmailVerified) {
        // Verified since the page was drawn, in another tab: draw it again to say so.
        window.location.reload();
      } else if (result.TooManyRequests) {
        const wait = formatDuration(result.WaitInSeconds, ["hour", "minute", "second"]);
        showNotice(status, "caution", button.dataset.wait.split("{wait}").join(wait));
      } else if (result.EmailVerificationSent) {
        showNotice(status, "positive", button.dataset.sent);
        if (code) {
          code.focus();
        }
      }
    }
  });
}

document.querySelectorAll("button[data-send-verification]").forEach(function (button) {
  button.addEventListener("click", function () {
    sendVerificationCode(button);
  });
});
