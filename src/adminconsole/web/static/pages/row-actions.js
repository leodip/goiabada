// row-actions.js is the behaviour of a list whose rows a person acts on one at a time, each with a
// button marked data-action-url that posts to that route, with data-action-body as its body when
// the route reads one. A removal asks first, in the dialog data-dialog names, with its own
// sentence, data-confirm; an add or a grant acts at once. The button is disabled while its request
// is under way, so a second click asks nothing twice.
//
// On success the button gives way to a tag saying what was done, data-done-label, in the tone
// data-done-tone names if any, and the page's status region says so, data-done. A button marked
// data-swap names instead, by id, the button in its row that takes its place, and the row's
// data-row-state element shows while that button is marked data-row-state-shown, so a grant can be
// removed again, or a removal granted, without a reload. A failure is said in the status region,
// which also holds the dialog's title, data-confirm-title. What takes the button's place takes the
// focus, and a failure gives it back to the button, only when the focus was lost, and lost by that
// action rather than one started after it; focus the person moved elsewhere meanwhile stays there.

const rowActionsStatus = document.getElementById("row-actions-status");

// focusOwner is the button of the row action started last with the focus its own to place, on that
// button or on nothing: a focus lost to nothing is that action's to place when it ends, not an
// earlier action's that happens to end first.
let focusOwner = null;

// focusOnNothing tells whether the focus is on nothing, or in a dialog just closed, where a browser
// leaves it until it next tidies up.
function focusOnNothing() {
  const focused = document.activeElement;
  return !focused || focused === document.body || focused.closest("dialog:not([open])") !== null;
}

// rowFocusLost tells whether a row action's end should place the focus: when it is on the action's
// own button, which its request disabled, or on nothing while that action owns it.
function rowFocusLost(button) {
  return document.activeElement === button || (focusOnNothing() && focusOwner === button);
}

function showRowActionDone(button) {
  const swap = button.dataset.swap ? document.getElementById(button.dataset.swap) : null;
  const placeFocus = rowFocusLost(button);
  if (swap) {
    button.hidden = true;
    swap.hidden = false;
    const state = button.closest("tr").querySelector("[data-row-state]");
    if (state) {
      state.hidden = !("rowStateShown" in swap.dataset);
    }
    if (placeFocus) {
      swap.focus();
    }
  } else {
    const done = document.createElement("span");
    done.className = button.dataset.doneTone ? "tag tag-" + button.dataset.doneTone : "tag";
    done.tabIndex = -1;
    done.textContent = button.dataset.doneLabel;
    button.replaceWith(done);
    if (placeFocus) {
      done.focus();
    }
  }
  showNotice(rowActionsStatus, "positive", button.dataset.done);
}

function runRowAction(button) {
  if (document.activeElement === button || focusOnNothing()) {
    focusOwner = button;
  }
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
      if (button.isConnected && !button.hidden && rowFocusLost(button)) {
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
