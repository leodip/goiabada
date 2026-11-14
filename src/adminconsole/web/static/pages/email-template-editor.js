// The email template editor (#818 decision 14): one email in one language, its subject, its button
// label where it has one, and its body.
//
// A placeholder button inserts {{name}} at the cursor of the subject or the body, whichever was
// focused last, replacing what is selected; a placeholder the subject does not take, the link or
// the button, goes into the body, and the button on a line of its own, which it must stand alone on.
//
// The page has the console's one unsaved-changes guard, since another language is one click from the
// text: while the form holds text that differs from the text as saved, which the page hands over in
// the emailTemplateSaved data block, choosing another language asks first in the page's
// discardChanges dialog, and leaving the page any other way lets the browser ask. Saving, or a Reset
// once its own question is answered, leaves without asking.

// insertPlaceholder answers value with written put between start and end, and where the cursor goes
// after it. ownLine puts it on a line of its own, breaking the line before and after it where it
// does not already break.
function insertPlaceholder(value, start, end, written, ownLine) {
  const before = value.slice(0, start);
  const after = value.slice(end);
  const lineBefore = ownLine && before !== "" && !before.endsWith("\n") ? "\n" : "";
  const lineAfter = ownLine && after !== "" && !after.startsWith("\n") ? "\n" : "";
  return {
    value: before + lineBefore + written + lineAfter + after,
    caret: before.length + lineBefore.length + written.length,
  };
}

// sameText reports whether two values of a field are the same text as the form sends it: a textarea
// reads a line break as LF and the auth server stores LF, so CRLF is no change.
function sameText(a, b) {
  return String(a).replace(/\r\n?/g, "\n") === String(b).replace(/\r\n?/g, "\n");
}

(function () {
  const form = document.getElementById("emailTemplateForm");
  const savedBlock = document.getElementById("emailTemplateSaved");
  if (!form || !savedBlock) {
    return;
  }
  const saved = JSON.parse(savedBlock.textContent);
  const subject = document.getElementById("subject");
  const buttonLabel = document.getElementById("buttonLabel");
  const body = document.getElementById("body");

  function hasUnsavedChanges() {
    if (!sameText(subject.value, saved.subject) || !sameText(body.value, saved.body)) {
      return true;
    }
    return buttonLabel !== null && !sameText(buttonLabel.value, saved.buttonLabel);
  }

  // The field a placeholder goes into: the subject only while it was the one focused last.
  let lastField = body;
  [subject, body].forEach(function (field) {
    field.addEventListener("focus", function () {
      lastField = field;
    });
  });

  document.querySelectorAll("[data-placeholder]").forEach(function (button) {
    button.addEventListener("click", function () {
      const name = button.dataset.placeholder;
      const field = lastField === subject && button.dataset.inSubject === "true" ? subject : body;
      const inserted = insertPlaceholder(field.value, field.selectionStart, field.selectionEnd, "{{" + name + "}}",
        field === body && name === "button");
      field.value = inserted.value;
      field.focus();
      field.setSelectionRange(inserted.caret, inserted.caret);
      lastField = field;
      // As typing does, so whatever follows the field's text sees the change.
      field.dispatchEvent(new Event("input", { bubbles: true }));
    });
  });

  // leaving is set once the page goes with the administrator's consent: a save or a Reset sent, or
  // Discard answered. It starts over when the browser shows the page again from its cache.
  let leaving = false;
  window.addEventListener("pageshow", function () {
    leaving = false;
  });
  // A submission another handler stopped, as the Reset's question does until it is answered, has
  // not left; this listener is on the document, so it runs after the form's own.
  document.addEventListener("submit", function (event) {
    if (!event.defaultPrevented) {
      leaving = true;
    }
  });
  window.addEventListener("beforeunload", function (event) {
    if (leaving || !hasUnsavedChanges()) {
      return;
    }
    event.preventDefault();
    // Chrome and Edge before 119 ask only when returnValue is set.
    event.returnValue = "";
  });

  const languages = document.getElementById("emailTemplateLanguages");
  if (languages) {
    languages.addEventListener("click", function (event) {
      const link = event.target && event.target.closest ? event.target.closest("a") : null;
      if (!link || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) {
        // A link opened elsewhere leaves this page and its text as they are.
        return;
      }
      if (!hasUnsavedChanges()) {
        return;
      }
      event.preventDefault();
      showModalDialog(languages.dataset.discardDialog, languages.dataset.discardTitle, languages.dataset.discardBody, null,
        function () {
          leaving = true;
          window.location.assign(link.href);
        });
    });
  }
})();
