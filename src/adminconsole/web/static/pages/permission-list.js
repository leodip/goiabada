// permission-list.js is the behaviour of a permissions tab: a resource is chosen, then one of its
// permissions, which Grant adds to the list, each field saying the chosen entry's description whole
// beneath it; permissions are removed from it in the page, and Save sends the set whole, beside the
// set as the page drew it, so the server refuses a save from an outdated page rather than undo
// another administrator's change (#428). The form names the save's route and fields in its data
// set.
//
// Grant with no permission chosen, or one in the list already, is refused at the permission field,
// which says why; a permission granted or removed is announced, since the change shows only in the
// list. Save asks first on the admin console's own client, through confirmChanges, then reloads the
// tab, which says the permissions were saved; a refusal is said in the tab's status region, as is a
// failure to load a resource's permissions. Choices the browser restores, as on Back, are shown as
// chosen, with a restored resource's permissions.

const permissionForm = document.getElementById("permissionListForm");
const resourceSelect = permissionForm.querySelector("[data-resource-select]");
const permissionSelect = permissionForm.querySelector("[data-permission-select]");
const permissionError = permissionForm.querySelector("[data-permission-error]");
const permissionRows = permissionForm.querySelector("[data-list-rows]");
const permissionRegion = permissionForm.querySelector("[data-list-region]");
const permissionEmpty = permissionForm.querySelector("[data-list-empty]");
const permissionAnnounce = permissionForm.querySelector("[data-list-announce]");
const permissionStatus = document.getElementById("permissionListStatus");

// grantedIds reads the set as the page shows it now, from its rows.
function grantedIds() {
  return Array.from(permissionRows.querySelectorAll("tr")).map(function (row) {
    return Number(row.dataset.id);
  });
}

const loadedIds = grantedIds();

function showEmpty() {
  const empty = permissionRows.querySelector("tr") === null;
  permissionRegion.hidden = empty;
  permissionEmpty.hidden = !empty;
}

// refuse says why at the permission field, and puts the focus where the choice is made: the
// permission field, or the resource field while there is no permission to choose.
function refuse(message) {
  permissionError.textContent = message;
  permissionError.hidden = false;
  permissionSelect.setAttribute("aria-invalid", "true");
  if (permissionSelect.disabled) {
    resourceSelect.focus();
  } else {
    permissionSelect.focus();
  }
}

function clearRefusal() {
  permissionError.textContent = "";
  permissionError.hidden = true;
  permissionSelect.removeAttribute("aria-invalid");
}

// shorten cuts text to at most max characters, an ellipsis standing for what was cut, as the
// console's render.Shorten cuts a resource's description for its choice.
function shorten(text, max) {
  const characters = Array.from(text.trim());
  if (characters.length <= max) {
    return characters.join("");
  }
  return characters.slice(0, max - 1).join("").trimEnd() + "…";
}

// showChoiceDescriptions writes, under each field marked data-choice-description-for, the chosen
// option's description whole, which its label carries shortened.
function showChoiceDescriptions() {
  permissionForm.querySelectorAll("[data-choice-description-for]").forEach(function (hint) {
    const select = document.getElementById(hint.dataset.choiceDescriptionFor);
    const option = select.selectedOptions[0];
    hint.textContent = option && option.value !== "" ? option.dataset.description || "" : "";
  });
}

// setPermissions fills the permission field with permissions of the resource resourceIdentifier
// names, after the option asking for one, each labelled with its identifier and its description
// shortened and carrying its resource's identifier, and disables it while there are none to choose.
function setPermissions(permissions, resourceIdentifier) {
  const placeholder = new Option(permissionForm.dataset.choosePermission, "");
  const options = permissions.map(function (permission) {
    const description = (permission.description || "").trim();
    const label = description ? permission.permissionIdentifier + " – " + shorten(description, 50) : permission.permissionIdentifier;
    const option = new Option(label, String(permission.id));
    option.dataset.permissionIdentifier = permission.permissionIdentifier;
    option.dataset.resourceIdentifier = resourceIdentifier;
    option.dataset.description = description;
    return option;
  });
  permissionSelect.replaceChildren(placeholder, ...options);
  permissionSelect.disabled = options.length === 0;
  showChoiceDescriptions();
}

// The resource the permission field was last asked to show, "" for none, and the number of that
// request: an answer to an earlier one, which a slow network can deliver last, is dropped, its
// refusal included, so the field never shows, nor grants, the permissions of a resource no longer
// chosen, and the page never says why a lookup no longer wanted failed.
let requestedResource = "";
let permissionsRequest = 0;

function loadPermissions() {
  const option = resourceSelect.selectedOptions[0];
  const resource = resourceSelect.value;
  const resourceIdentifier = option ? option.dataset.resourceIdentifier : "";
  const request = ++permissionsRequest;
  requestedResource = resource;
  clearRefusal();
  setPermissions([], "");
  if (resource === "") {
    return;
  }
  sendAjaxRequest({
    url: "/admin/get-permissions?" + new URLSearchParams({ resourceId: resource }),
    method: "GET",
    bodyData: null,
    statusRegion: permissionStatus,
    current: function () {
      return request === permissionsRequest && resourceSelect.value === resource;
    },
    callback: function (result) {
      setPermissions(result.Permissions, resourceIdentifier);
    }
  });
}

// showRestoredChoices brings the page in line with choices the browser restored without saying so,
// as it does on Back: the descriptions, and the permissions of a resource restored chosen.
function showRestoredChoices() {
  showChoiceDescriptions();
  if (resourceSelect.value !== requestedResource) {
    loadPermissions();
  }
}

// The row a permission is drawn in, built with DOM calls, so its scope is shown as text (#120).
function rowFor(id, scope) {
  const row = document.createElement("tr");
  row.dataset.id = String(id);
  const cell = document.createElement("td");
  cell.className = "cell-mono cell-wrap";
  cell.textContent = scope;
  const actions = document.createElement("td");
  actions.className = "cell-actions";
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "button button-sm";
  remove.dataset.listRemove = "";
  remove.textContent = permissionForm.dataset.removeLabel;
  const name = document.createElement("span");
  name.className = "sr-only";
  name.textContent = " " + scope;
  remove.appendChild(name);
  actions.appendChild(remove);
  row.append(cell, actions);
  return row;
}

function grant() {
  const option = permissionSelect.selectedOptions[0];
  if (permissionSelect.disabled || !option || option.value === "") {
    refuse(permissionForm.dataset.unchosen);
    return;
  }
  const id = Number(option.value);
  if (grantedIds().includes(id)) {
    refuse(permissionForm.dataset.duplicate);
    return;
  }
  clearRefusal();
  permissionRows.appendChild(rowFor(id, option.dataset.resourceIdentifier + ":" + option.dataset.permissionIdentifier));
  showEmpty();
  permissionSelect.value = "";
  showChoiceDescriptions();
  permissionSelect.focus();
  permissionAnnounce.textContent = permissionForm.dataset.added;
}

// removePermission takes row out of the set, and puts the focus on the next row's Remove, or else
// the one before, or else the resource field, so it is not lost with the button that had it.
function removePermission(row) {
  const next = row.nextElementSibling || row.previousElementSibling;
  row.remove();
  showEmpty();
  if (next) {
    next.querySelector("[data-list-remove]").focus();
  } else {
    resourceSelect.focus();
  }
  permissionAnnounce.textContent = permissionForm.dataset.removed;
}

function save() {
  const body = {};
  body[permissionForm.dataset.ownerKey] = Number(permissionForm.dataset.ownerId);
  body[permissionForm.dataset.listKey] = grantedIds();
  body[permissionForm.dataset.expectedKey] = loadedIds;
  sendAjaxRequest({
    url: permissionForm.dataset.saveUrl,
    method: "POST",
    bodyData: JSON.stringify(body),
    statusRegion: permissionStatus,
    callback: function (result) {
      if (result.Success) {
        window.location.href = permissionForm.dataset.saveUrl;
      }
    }
  });
}

resourceSelect.addEventListener("change", function () {
  showChoiceDescriptions();
  loadPermissions();
});
permissionSelect.addEventListener("change", function () {
  showChoiceDescriptions();
  clearRefusal();
});
permissionForm.querySelector("[data-permission-grant]").addEventListener("click", grant);
permissionRows.addEventListener("click", function (event) {
  const remove = event.target.closest("[data-list-remove]");
  if (remove) {
    removePermission(remove.closest("tr"));
  }
});
permissionForm.addEventListener("submit", function (event) {
  event.preventDefault();
  confirmChanges(permissionForm, save);
});
// pageshow comes after the browser restores the form, on the first visit and on Back alike.
window.addEventListener("pageshow", showRestoredChoices);
