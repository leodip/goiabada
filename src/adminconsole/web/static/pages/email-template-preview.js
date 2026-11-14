// The email template editor's preview and Send test email (#818 decisions 11 and 12).
//
// The preview is the email the text in the form draws, saved or not, as the auth server would send
// it, with sample values, in the brand chosen. It is asked for as the page opens and a moment after
// each change, the placeholder buttons' included, in two steps: the console's JSON preview answers
// the subject and the plain-text part, shown above and under the frame, or the refusal a save would
// give, said in #previewStatus while the last good preview stays; only then is the frame loaded
// with the same text, through #previewFrameForm, from the one console route that answers the email
// as a document of its own. The frame is sandboxed, so nothing in it runs or opens, and the page
// never writes the email's markup itself. An answer to any request but the latest is dropped.
//
// Send test email sends the text in the form, with the brand chosen for the preview, to the address
// typed, without leaving the page, and says the answer in #sendTestStatus. Its form's submission
// is stopped here, so the editor's unsaved-changes guard does not read it as leaving.

(function () {
  const panel = document.getElementById("emailTemplatePreviewPanel");
  const frameForm = document.getElementById("previewFrameForm");
  const subject = document.getElementById("subject");
  const body = document.getElementById("body");
  if (!panel || !frameForm || !subject || !body) {
    return;
  }
  const buttonLabel = document.getElementById("buttonLabel");
  const brand = document.getElementById("previewBrand");
  const previewStatus = document.getElementById("previewStatus");
  const previewSubject = document.getElementById("previewSubject");
  const previewText = document.getElementById("previewText");

  // sample is the text in the form as a save sends it, the subject and the label trimmed, with the
  // brand chosen, none for the default brand.
  function sample() {
    const text = {
      subject: subject.value.trim(),
      buttonLabel: buttonLabel ? buttonLabel.value.trim() : "",
      body: body.value,
    };
    if (brand && brand.value !== "") {
      text.brandId = Number(brand.value);
    }
    return text;
  }

  let latest = 0;
  function renderPreview() {
    latest++;
    const request = latest;
    const sent = sample();
    sendAjaxRequest({
      url: panel.dataset.previewUrl,
      method: "POST",
      bodyData: JSON.stringify(sent),
      statusRegion: previewStatus,
      current: function () { return request === latest; },
      callback: function (answer) {
        previewStatus.replaceChildren();
        previewSubject.textContent = answer.subject;
        previewText.textContent = answer.text;
        frameForm.elements.subject.value = sent.subject;
        frameForm.elements.buttonLabel.value = sent.buttonLabel;
        frameForm.elements.body.value = sent.body;
        frameForm.elements.brandId.value = sent.brandId === undefined ? "" : String(sent.brandId);
        // submit() sends no submit event, which the editor's guard would read as leaving the page.
        frameForm.submit();
      },
    });
  }

  renderPreview();
  const renderSoon = debounce(renderPreview, 400);
  [subject, buttonLabel, body].forEach(function (field) {
    if (field) {
      field.addEventListener("input", renderSoon);
    }
  });
  if (brand) {
    brand.addEventListener("change", renderPreview);
  }
  // A browser restoring the form, as on Back, fires no input, and the text may have changed.
  window.addEventListener("pageshow", function (event) {
    if (event.persisted) {
      renderPreview();
    }
  });

  const sendForm = document.getElementById("sendTestForm");
  const address = document.getElementById("testAddress");
  const sendButton = document.getElementById("btnSendTest");
  const sendStatus = document.getElementById("sendTestStatus");
  if (!sendForm || !address || !sendButton || !sendStatus) {
    return;
  }
  sendForm.addEventListener("submit", function (event) {
    event.preventDefault();
    // Disabled while SMTP is off, and while a send runs; Enter in the address still submits.
    if (sendButton.disabled) {
      return;
    }
    const sent = Object.assign({ to: address.value.trim() }, sample());
    sendButton.disabled = true;
    sendAjaxRequest({
      url: sendForm.getAttribute("action"),
      method: "POST",
      bodyData: JSON.stringify(sent),
      statusRegion: sendStatus,
      finished: function () { sendButton.disabled = false; },
      callback: function (answer) {
        showNotice(sendStatus, "positive", answer.message);
      },
    });
  });
})();
