// account-email-verification.js is the email verification page's behaviour: its Send code button
// asks the console to email a code, and the answer is said in the page's status region, where the
// button's data-sent and data-wait give the sentences. data-wait names the seconds to wait as
// {seconds}, which only the answer knows.

function sendVerificationCode(button) {
  const status = document.getElementById("verification-status");
  const code = document.getElementById("verificationCode");
  sendAjaxRequest({
    url: "/account/email-send-verification",
    method: "POST",
    bodyData: JSON.stringify({}),
    modalId: "modal0",
    callback: function (result) {
      if (result.EmailVerified) {
        // Verified since the page was drawn, in another tab: draw it again to say so.
        window.location.reload();
      } else if (result.TooManyRequests) {
        showNotice(status, "caution", button.dataset.wait.split("{seconds}").join(String(result.WaitInSeconds)));
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
