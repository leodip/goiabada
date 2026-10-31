// client-uri-list.js is the behaviour of a client's redirect URIs, sign-out redirect URIs and web
// origins tabs, one list each: entries are added and removed in the page, and Save sends the list
// whole, beside the list as the page drew it, so the server refuses a save from an outdated page
// rather than undo another administrator's change (#428). The form names the save's route and fields in its data set, and
// marks with data-origins a list that keeps of each entry only its origin.
//
// An entry that is no URL, or no origin, or is in the list already, is refused at its field, which
// says why; an entry added or removed is announced, since the change shows only in the list. Save
// asks first on the admin console's own client, through confirmChanges, then reloads the tab, which
// says the list was saved; a refusal is said in the tab's status region.

const listForm = document.getElementById("uriListForm");
const listInput = listForm.querySelector("[data-list-input]");
const listError = listForm.querySelector("[data-list-error]");
const listRows = listForm.querySelector("[data-list-rows]");
const listRegion = listForm.querySelector("[data-list-region]");
const listEmpty = listForm.querySelector("[data-list-empty]");
const listAnnounce = listForm.querySelector("[data-list-announce]");
const listStatus = document.getElementById("uriListStatus");

// entries reads the list as the page shows it now, from its rows.
function entries() {
  return Array.from(listRows.querySelectorAll("tr")).map(function (row) {
    return row.dataset.value;
  });
}

const loadedEntries = entries();

function showEmpty() {
  const empty = listRows.querySelector("tr") === null;
  listRegion.hidden = empty;
  listEmpty.hidden = !empty;
}

function refuse(message) {
  listError.textContent = message;
  listError.hidden = false;
  listInput.setAttribute("aria-invalid", "true");
  listInput.focus();
}

function clearRefusal() {
  listError.textContent = "";
  listError.hidden = true;
  listInput.removeAttribute("aria-invalid");
}

// The row an entry is drawn in, built with DOM calls, so an entry is shown as text (#105).
function rowFor(value) {
  const row = document.createElement("tr");
  row.dataset.value = value;
  const cell = document.createElement("td");
  cell.className = "cell-mono cell-wrap";
  cell.textContent = value;
  const actions = document.createElement("td");
  actions.className = "cell-actions";
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "button button-sm";
  remove.dataset.listRemove = "";
  remove.textContent = listForm.dataset.removeLabel;
  const name = document.createElement("span");
  name.className = "sr-only";
  name.textContent = " " + value;
  remove.appendChild(name);
  actions.appendChild(remove);
  row.append(cell, actions);
  return row;
}

function addEntry() {
  let value = listInput.value.trim();
  try {
    const url = new URL(value);
    if ("origins" in listForm.dataset) {
      value = url.origin;
    }
  } catch (err) {
    value = "";
  }
  // A URL whose scheme has no origin, such as myapp:8080 read as the scheme myapp, has the origin
  // "null", which no browser sends.
  if (value === "" || value === "null") {
    refuse(listForm.dataset.invalid);
    return;
  }
  if (entries().includes(value)) {
    refuse(listForm.dataset.duplicate);
    return;
  }
  clearRefusal();
  listRows.appendChild(rowFor(value));
  showEmpty();
  listInput.value = "";
  listInput.focus();
  listAnnounce.textContent = listForm.dataset.added;
}

// removeEntry takes row out of the list, and puts the focus on the next row's Remove, or else the
// one before, or else the field, so it is not lost with the button that had it.
function removeEntry(row) {
  const next = row.nextElementSibling || row.previousElementSibling;
  row.remove();
  showEmpty();
  if (next) {
    next.querySelector("[data-list-remove]").focus();
  } else {
    listInput.focus();
  }
  listAnnounce.textContent = listForm.dataset.removed;
}

function save() {
  const body = { clientId: Number(listForm.dataset.clientId) };
  body[listForm.dataset.listKey] = entries();
  body[listForm.dataset.expectedKey] = loadedEntries;
  sendAjaxRequest({
    url: listForm.dataset.saveUrl,
    method: "POST",
    bodyData: JSON.stringify(body),
    statusRegion: listStatus,
    callback: function (result) {
      if (result.Success) {
        window.location.href = listForm.dataset.saveUrl;
      }
    }
  });
}

listForm.querySelector("[data-list-add]").addEventListener("click", addEntry);
listInput.addEventListener("keydown", function (event) {
  if (event.key === "Enter") {
    event.preventDefault();
    addEntry();
  }
});
listInput.addEventListener("input", clearRefusal);
listRows.addEventListener("click", function (event) {
  const remove = event.target.closest("[data-list-remove]");
  if (remove) {
    removeEntry(remove.closest("tr"));
  }
});
listForm.addEventListener("submit", function (event) {
  event.preventDefault();
  confirmChanges(listForm, save);
});
