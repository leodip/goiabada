// utils.js is the auth server's shared page behaviour. Both layouts load it with defer, so it runs
// once the document is parsed and before DOMContentLoaded.

// submitOnce lets a form that must be sent once through on its first submission: the password and
// the two code forms. The first submission goes, and the form's buttons are disabled, so a double
// click or a repeated Enter sends no second one; implicit submission does not go through a disabled
// default button. A second submission reaching the server after the first rotated the browser
// session away would meet the "no longer active" page (#579). A page the browser restores from its
// back-forward cache gets its buttons back, so the form can be sent again from there. It returns
// whether the submission may go.
function submitOnce(form) {
  if (form.dataset.submitted === "true") {
    return false;
  }
  form.dataset.submitted = "true";
  form.querySelectorAll("button").forEach(function (button) {
    button.disabled = true;
  });
  window.addEventListener("pageshow", function (event) {
    if (event.persisted) {
      delete form.dataset.submitted;
      form.querySelectorAll("button").forEach(function (button) {
        button.disabled = false;
      });
    }
  }, { once: true });
  return true;
}

// hideBrokenImage hides an image that failed to load, such as a client's logo whose file is gone,
// rather than showing the browser's broken-image icon. The image may have failed before this script
// ran, which is what the first check catches.
function hideBrokenImage(img) {
  if (img.complete && img.naturalWidth === 0) {
    img.hidden = true;
    return;
  }
  img.addEventListener("error", function () {
    img.hidden = true;
  });
}

document.querySelectorAll("form[data-submit-once]").forEach(function (form) {
  form.addEventListener("submit", function (event) {
    if (!submitOnce(form)) {
      event.preventDefault();
    }
  });
});

document.querySelectorAll("img[data-hide-on-error]").forEach(function (img) {
  hideBrokenImage(img);
});

// A link marked data-history-back goes back through the browser's history when there is any: the
// sign-out page's "Stay signed in", which returns to the page that asked. With no history, or with
// JavaScript off, the link's own href is the answer.
document.querySelectorAll("a[data-history-back]").forEach(function (link) {
  link.addEventListener("click", function (event) {
    if (history.length > 1) {
      event.preventDefault();
      history.back();
    }
  });
});
