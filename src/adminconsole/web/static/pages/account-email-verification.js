// account-email-verification.js is the email verification page's behaviour: its Send code button
// asks the console to email a code, and the answer, or why it failed, is said in the page's status
// region, where the button's data-sent and data-wait give the sentences. data-wait names the time
// to wait as {wait}, which only the answer knows, and which is written as a duration in the page's
// language, such as "4 minutes, 20 seconds".

// waitText writes a number of seconds as a duration in the page's language.
function waitText(seconds) {
  const language = (document.documentElement.lang || "en").toLowerCase().split("-")[0];
  return humanizeDuration(seconds * 1000, { units: ["h", "m", "s"], language: language, fallbacks: ["en"] });
}

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
        showNotice(status, "caution", button.dataset.wait.split("{wait}").join(waitText(result.WaitInSeconds)));
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
