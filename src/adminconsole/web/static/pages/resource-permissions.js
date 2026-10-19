// resource-permissions.js is the behaviour of a resource's permissions tab: permissions are added,
// edited and removed in the page, and Save sends the list whole, beside the list as the page drew it,
// so the server refuses a save from an outdated page rather than undo another administrator's change
// (#428). The form names the save's route and fields, and the validation's route, in its data set.
//
// An identifier the list holds already is refused at its field; the rest the console's validation
// answers, naming the field it refuses, which says why. That answer applies the values it was asked
// about, never the fields as they are when it arrives, and is dropped when the person has typed past
// them, edited another row or asked again since, so a slow answer never adds or changes a
// permission no one asked for. An entry added, updated or removed is announced, since the change
// shows only in the list. Save asks first where the form says so, through confirmChanges, then
// reloads the tab, which says the permissions were saved; a refusal is said in the tab's status
// region. The built-in permissions of the auth server's own resource are drawn without Edit or
// Remove.

const permissionsForm = document.getElementById("resourcePermissionsForm");
const identifierInput = document.getElementById("permissionIdentifier");
const descriptionInput = document.getElementById("permissionDescription");
const addButton = document.getElementById("addPermissionBtn");
const updateButton = document.getElementById("updatePermissionBtn");
const cancelButton = document.getElementById("cancelEditBtn");
const entryRows = permissionsForm.querySelector("[data-list-rows]");
const entryRegion = permissionsForm.querySelector("[data-list-region]");
const entryEmpty = permissionsForm.querySelector("[data-list-empty]");
const entryAnnounce = permissionsForm.querySelector("[data-list-announce]");
const entryStatus = document.getElementById("resourcePermissionsStatus");
const fieldErrors = {
  permissionIdentifier: document.getElementById("permissionIdentifier-error"),
  description: document.getElementById("permissionDescription-error")
};
const fieldInputs = { permissionIdentifier: identifierInput, description: descriptionInput };

// entries reads the list as the page shows it now, from its rows.
function entries() {
  return Array.from(entryRows.querySelectorAll("tr")).map(function (row) {
    return { id: Number(row.dataset.id), permissionIdentifier: row.dataset.identifier, description: row.dataset.description };
  });
}

const loadedEntries = entries();

// A permission added in the page has no id yet: each takes the next negative one, which the save
// sends as no id at all.
let nextNewId = 0;
// editingRow is the row the fields edit, null while they add one.
let editingRow = null;
// The number of the latest validation asked for; an answer to an earlier one is dropped.
let validation = 0;

function showEntriesEmpty() {
  const empty = entryRows.querySelector("tr") === null;
  entryRegion.hidden = empty;
  entryEmpty.hidden = !empty;
}

function clearRefusals() {
  Object.keys(fieldErrors).forEach(function (field) {
    fieldErrors[field].textContent = "";
    fieldErrors[field].hidden = true;
    fieldInputs[field].removeAttribute("aria-invalid");
  });
}

// refuse says why at the field named, or at the identifier when the answer names none, and puts
// the focus there.
function refuse(field, message) {
  const input = fieldInputs[field] ? field : "permissionIdentifier";
  clearRefusals();
  fieldErrors[input].textContent = message;
  fieldErrors[input].hidden = false;
  fieldInputs[input].setAttribute("aria-invalid", "true");
  fieldInputs[input].focus();
}

// The row a permission is drawn in, built with DOM calls, so its identifier and description are
// shown as text (#120).
function entryRow(id, identifier, description) {
  const row = document.createElement("tr");
  const identifierCell = document.createElement("td");
  identifierCell.className = "cell-mono cell-wrap";
  const descriptionCell = document.createElement("td");
  descriptionCell.className = "cell-wrap";
  descriptionCell.dataset.label = permissionsForm.dataset.descriptionLabel;
  const actions = document.createElement("td");
  actions.className = "cell-actions";
  const group = document.createElement("span");
  group.className = "inline-flex flex-wrap items-center justify-end gap-2";
  [["entryEdit", permissionsForm.dataset.editLabel], ["entryRemove", permissionsForm.dataset.removeLabel]].forEach(function (action) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "button button-sm";
    button.dataset[action[0]] = "";
    button.textContent = action[1];
    const name = document.createElement("span");
    name.className = "sr-only";
    button.appendChild(name);
    group.appendChild(button);
  });
  actions.appendChild(group);
  row.append(identifierCell, descriptionCell, actions);
  fillRow(row, id, identifier, description);
  return row;
}

// fillRow writes a permission into its row: the data the save reads, the cells, and the names its
// buttons carry for a screen reader.
function fillRow(row, id, identifier, description) {
  row.dataset.id = String(id);
  row.dataset.identifier = identifier;
  row.dataset.description = description;
  row.cells[0].textContent = identifier;
  row.cells[1].textContent = description;
  row.querySelectorAll(".sr-only").forEach(function (name) {
    name.textContent = " " + identifier;
  });
}

function takenByAnother(identifier) {
  return Array.from(entryRows.querySelectorAll("tr")).some(function (row) {
    return row !== editingRow && row.dataset.identifier === identifier;
  });
}

// validate asks the console whether identifier and description may be saved, and runs apply with
// them when they may, unless the person has since changed either field, started editing another
// row, or asked again.
function validate(identifier, description, apply) {
  const request = ++validation;
  const row = editingRow;
  sendAjaxRequest({
    url: permissionsForm.dataset.validateUrl,
    method: "POST",
    bodyData: JSON.stringify({ permissionIdentifier: identifier, description: description }),
    statusRegion: entryStatus,
    current: function () {
      return request === validation && editingRow === row &&
        identifierInput.value.trim() === identifier && descriptionInput.value.trim() === description;
    },
    callback: function (result) {
      if (!result.Valid) {
        refuse(result.Field, result.Error);
        return;
      }
      apply(identifier, description);
    }
  });
}

function startAdding() {
  editingRow = null;
  identifierInput.value = "";
  descriptionInput.value = "";
  addButton.hidden = false;
  updateButton.hidden = true;
  cancelButton.hidden = true;
  clearRefusals();
}

function addEntry() {
  const identifier = identifierInput.value.trim();
  const description = descriptionInput.value.trim();
  if (identifier !== "" && takenByAnother(identifier)) {
    refuse("permissionIdentifier", permissionsForm.dataset.duplicate);
    return;
  }
  validate(identifier, description, function (validIdentifier, validDescription) {
    nextNewId--;
    entryRows.appendChild(entryRow(nextNewId, validIdentifier, validDescription));
    showEntriesEmpty();
    startAdding();
    identifierInput.focus();
    entryAnnounce.textContent = permissionsForm.dataset.added;
  });
}

function editEntry(row) {
  editingRow = row;
  identifierInput.value = row.dataset.identifier;
  descriptionInput.value = row.dataset.description;
  addButton.hidden = true;
  updateButton.hidden = false;
  cancelButton.hidden = false;
  clearRefusals();
  identifierInput.focus();
}

function updateEntry() {
  const row = editingRow;
  const identifier = identifierInput.value.trim();
  const description = descriptionInput.value.trim();
  if (identifier !== "" && takenByAnother(identifier)) {
    refuse("permissionIdentifier", permissionsForm.dataset.duplicate);
    return;
  }
  validate(identifier, description, function (validIdentifier, validDescription) {
    fillRow(row, Number(row.dataset.id), validIdentifier, validDescription);
    startAdding();
    row.querySelector("[data-entry-edit]").focus();
    entryAnnounce.textContent = permissionsForm.dataset.updated;
  });
}

function cancelEdit() {
  const row = editingRow;
  startAdding();
  if (row) {
    row.querySelector("[data-entry-edit]").focus();
  }
}

// removeEntry takes row out of the list, ending its edit if the fields held it, and puts the focus
// on the next row's Remove, or else the one before, or else the identifier field.
function removeEntry(row) {
  if (row === editingRow) {
    startAdding();
  }
  const next = row.nextElementSibling || row.previousElementSibling;
  row.remove();
  showEntriesEmpty();
  const nextRemove = next ? next.querySelector("[data-entry-remove]") : null;
  if (nextRemove) {
    nextRemove.focus();
  } else {
    identifierInput.focus();
  }
  entryAnnounce.textContent = permissionsForm.dataset.removed;
}

function saveEntries() {
  const body = { resourceId: Number(permissionsForm.dataset.resourceId) };
  body[permissionsForm.dataset.listKey] = entries();
  body[permissionsForm.dataset.expectedKey] = loadedEntries;
  sendAjaxRequest({
    url: permissionsForm.dataset.saveUrl,
    method: "POST",
    bodyData: JSON.stringify(body),
    statusRegion: entryStatus,
    callback: function (result) {
      if (result.Success) {
        window.location.href = permissionsForm.dataset.saveUrl;
      }
    }
  });
}

addButton.addEventListener("click", addEntry);
updateButton.addEventListener("click", updateEntry);
cancelButton.addEventListener("click", cancelEdit);
[identifierInput, descriptionInput].forEach(function (input) {
  input.addEventListener("input", clearRefusals);
  input.addEventListener("keydown", function (event) {
    if (event.key === "Enter") {
      event.preventDefault();
      if (editingRow) {
        updateEntry();
      } else {
        addEntry();
      }
    }
  });
});
entryRows.addEventListener("click", function (event) {
  const edit = event.target.closest("[data-entry-edit]");
  if (edit) {
    editEntry(edit.closest("tr"));
    return;
  }
  const remove = event.target.closest("[data-entry-remove]");
  if (remove) {
    removeEntry(remove.closest("tr"));
  }
});
permissionsForm.addEventListener("submit", function (event) {
  event.preventDefault();
  confirmChanges(permissionsForm, saveEntries);
});
