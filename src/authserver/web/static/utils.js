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

// passwordToggle wires a password field's show/hide button. The button, a button of type button
// drawn hidden, is shown, so without JavaScript it never appears. Pressing it switches the field's
// type, the word it reads between its own text and data-hide-label, and its name between its
// aria-label and data-hide-name, such as "Show password" and "Hide password": a name that changes,
// so no aria-pressed (WAI-ARIA Authoring Practices, Button pattern). The new state is also written,
// data-shown-status or data-hidden-status, into a visually hidden role="status" region created
// beside the field's row before anything is written to it, since a screen reader may not speak a
// focused button's new name. A pointer press keeps the focus where it was, and the field's caret
// and selection survive the change of type; a keyboard press leaves the focus on the button. The
// field goes back to dots when its form is sent, and when the browser brings the page back, as on
// Back.
function passwordToggle(button) {
  const field = document.getElementById(button.getAttribute("aria-controls"));
  if (!field) {
    return;
  }
  const showLabel = button.textContent;
  const hideLabel = button.dataset.hideLabel || showLabel;
  const showName = button.getAttribute("aria-label");
  const hideName = button.dataset.hideName;
  const status = document.createElement("span");
  status.className = "sr-only";
  status.setAttribute("role", "status");
  (button.parentElement || button).after(status);
  let shown = false;

  const show = function (on) {
    if (on === shown) {
      return;
    }
    shown = on;
    const focused = document.activeElement === field;
    const start = field.selectionStart;
    const end = field.selectionEnd;
    const direction = field.selectionDirection;
    field.type = on ? "text" : "password";
    if (focused && start !== null) {
      field.setSelectionRange(start, end, direction || "none");
    }
    button.textContent = on ? hideLabel : showLabel;
    if (showName && hideName) {
      button.setAttribute("aria-label", on ? hideName : showName);
    }
    status.textContent = on ? button.dataset.shownStatus || "" : button.dataset.hiddenStatus || "";
  };

  // A pointer press would move the focus to the button, out of the field the person types in.
  button.addEventListener("mousedown", function (event) {
    event.preventDefault();
  });
  button.addEventListener("click", function () {
    show(!shown);
  });
  if (field.form) {
    field.form.addEventListener("submit", function () {
      show(false);
    });
  }
  window.addEventListener("pageshow", function () {
    show(false);
  });
  button.hidden = false;
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

// A button marked data-copy-target copies the text of the element it names, for a secret a person
// would otherwise type again, such as an authenticator key, and says so for a moment on itself and
// in the status element data-copy-status names. It stays hidden where the browser cannot write to
// the clipboard, where the text is still there to select. Where the browser has the clipboard but
// refuses the write, as a denied permission does, it selects the text instead and says so, with
// data-copy-failed-label on itself and data-copy-failed-status in the status element.
document.querySelectorAll("button[data-copy-target]").forEach(function (button) {
  const source = document.getElementById(button.dataset.copyTarget);
  const status = document.getElementById(button.dataset.copyStatus);
  const label = button.querySelector("span");
  if (!source || !label || !navigator.clipboard) {
    return;
  }
  const idle = label.textContent;
  let timer = 0;
  const say = function (text, announcement) {
    label.textContent = text || idle;
    if (status) {
      status.textContent = announcement || "";
    }
    clearTimeout(timer);
    timer = setTimeout(function () {
      label.textContent = idle;
      if (status) {
        status.textContent = "";
      }
    }, 2000);
  };
  button.hidden = false;
  button.addEventListener("click", function () {
    navigator.clipboard.writeText(source.textContent.trim()).then(function () {
      say(button.dataset.copiedLabel, button.dataset.copiedLabel);
    }, function () {
      const selection = window.getSelection();
      if (selection) {
        selection.selectAllChildren(source);
      }
      say(button.dataset.copyFailedLabel, button.dataset.copyFailedStatus);
    });
  });
});

// A button marked data-password-toggle shows and hides the password field its aria-controls names.
document.querySelectorAll("button[data-password-toggle]").forEach(function (button) {
  passwordToggle(button);
});
