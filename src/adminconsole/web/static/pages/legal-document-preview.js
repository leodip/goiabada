// legal-document-preview.js shows a legal document's text as its public page shows it (#622): it
// sends the Markdown to the console, which asks the auth server's renderer, and puts the HTML that
// renderer answers into #legalDocumentPreview. That renderer is the one the public pages use, and
// it is what guards the HTML: it leaves raw HTML out, drops javascript:, vbscript:, file: and
// non-image data: addresses, and draws every image as a link to it, so a document never makes a
// page run code or fetch anything (decision 4). The line putting its answer in the page is the one
// audited exception web/html_sink_lint_test.go allows here.
//
// The text is the element data-preview-source names: on the editor, the textarea, rendered again a
// moment after each change, saved or not, an answer to any request but the latest dropped; on a
// version's page, the JSON data block holding that version's Markdown, rendered once. A refusal,
// a text too long, is said in #previewStatus, which an answer empties again.

const preview = document.getElementById("legalDocumentPreview");

if (preview) {
  const source = document.getElementById(preview.dataset.previewSource);
  const previewStatus = document.getElementById("previewStatus");
  const markdown = source.tagName === "SCRIPT"
    ? function () { return JSON.parse(source.textContent); }
    : function () { return source.value; };

  let latest = 0;
  const renderPreview = function () {
    latest++;
    const request = latest;
    sendAjaxRequest({
      url: preview.dataset.previewUrl,
      method: "POST",
      bodyData: JSON.stringify({ markdown: markdown() }),
      statusRegion: previewStatus,
      current: function () { return request === latest; },
      callback: function (answer) {
        previewStatus.replaceChildren();
        preview.innerHTML = answer.html;
      },
    });
  };

  renderPreview();
  if (source.tagName !== "SCRIPT") {
    source.addEventListener("input", debounce(renderPreview, 400));
    // A browser restoring the form, as on Back, fires no input, and the text may have changed.
    window.addEventListener("pageshow", function (event) {
      if (event.persisted) {
        renderPreview();
      }
    });
  }
}
