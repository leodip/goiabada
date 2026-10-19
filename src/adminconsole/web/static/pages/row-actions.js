// row-actions.js is the behaviour of a list whose rows a person acts on one at a time, each with a
// button marked data-action-url that posts to that route, with data-action-body as its body when
// the route reads one. A removal asks first, in the dialog data-dialog names, with its own
// sentence, data-confirm; an add or a grant acts at once. The button is disabled while its request
// is under way, so a second click asks nothing twice.
//
// On success the button gives way to a tag saying what was done, data-done-label, in the tone
// data-done-tone names if any, which takes the focus the button had, and the page's status region
// says so, data-done. A button marked data-swap names instead, by id, the button in its row that
// takes its place, and the row's data-row-state element shows while that button is marked
// data-row-state-shown, so a grant can be removed again, or a removal granted, without a reload. A
// failure is said in the status region, which also holds the dialog's title, data-confirm-title.

const rowActionsStatus = document.getElementById("row-actions-status");

function showRowActionDone(button) {
  const swap = button.dataset.swap ? document.getElementById(button.dataset.swap) : null;
  if (swap) {
    button.hidden = true;
    swap.hidden = false;
    const state = button.closest("tr").querySelector("[data-row-state]");
    if (state) {
      state.hidden = !("rowStateShown" in swap.dataset);
    }
    swap.focus();
  } else {
    const done = document.createElement("span");
    done.className = button.dataset.doneTone ? "tag tag-" + button.dataset.doneTone : "tag";
    done.tabIndex = -1;
    done.textContent = button.dataset.doneLabel;
    button.replaceWith(done);
    done.focus();
  }
  showNotice(rowActionsStatus, "positive", button.dataset.done);
}

function runRowAction(button) {
  button.disabled = true;
  sendAjaxRequest({
    url: button.dataset.actionUrl,
    method: "POST",
    bodyData: button.dataset.actionBody || null,
    statusRegion: rowActionsStatus,
    finished: function () {
      button.disabled = false;
      // A button disabled while it had the focus may have lost it: give it back, so a failure
      // leaves the person where they were.
      if (button.isConnected && !button.hidden && (document.activeElement === null || document.activeElement === document.body)) {
        button.focus();
      }
    },
    callback: function (result) {
      if (result.Success) {
        showRowActionDone(button);
      }
    }
  });
}

document.addEventListener("click", function (event) {
  const button = event.target.closest("button[data-action-url]");
  if (!button || button.disabled) {
    return;
  }
  if (button.dataset.confirm) {
    const title = button.dataset.confirmTitle || rowActionsStatus.dataset.confirmTitle;
    showModalDialog(button.dataset.dialog, title, button.dataset.confirm, null, function () {
      runRowAction(button);
    });
  } else {
    runRowAction(button);
  }
});
