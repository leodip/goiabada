// user-groups.js is the behaviour of a user's groups tab: a group is chosen, its description shown
// whole beneath the field, and Add puts the user in it; groups are removed in the page too, and
// Save sends the set whole, beside the set as the page drew it, so the server refuses a save from
// an outdated page rather than undo another administrator's change (#428). The form names the
// save's route and fields, and the page to reload after a save, in its data set.
//
// Add with no group chosen, or one in the list already, is refused at the field, which says why; a
// group added or removed is announced, since the change shows only in the list. Save reloads the
// tab, which says the groups were saved; a refusal is said in the tab's status region. A choice the
// browser restores, as on Back, shows its description.

const groupsForm = document.getElementById("groupListForm");
const groupSelect = groupsForm.querySelector("[data-group-select]");
const groupError = groupsForm.querySelector("[data-group-error]");
const groupHint = groupsForm.querySelector("[data-group-description]");
const groupRows = groupsForm.querySelector("[data-list-rows]");
const groupRegion = groupsForm.querySelector("[data-list-region]");
const groupEmpty = groupsForm.querySelector("[data-list-empty]");
const groupAnnounce = groupsForm.querySelector("[data-list-announce]");
const groupStatus = document.getElementById("groupListStatus");

// memberOf reads the set as the page shows it now, from its rows.
function memberOf() {
  return Array.from(groupRows.querySelectorAll("tr")).map(function (row) {
    return Number(row.dataset.id);
  });
}

const loadedGroupIds = memberOf();

function showGroupsEmpty() {
  const empty = groupRows.querySelector("tr") === null;
  groupRegion.hidden = empty;
  groupEmpty.hidden = !empty;
}

function refuseGroup(message) {
  groupError.textContent = message;
  groupError.hidden = false;
  groupSelect.setAttribute("aria-invalid", "true");
  groupSelect.focus();
}

function clearGroupRefusal() {
  groupError.textContent = "";
  groupError.hidden = true;
  groupSelect.removeAttribute("aria-invalid");
}

function showGroupDescription() {
  const option = groupSelect.selectedOptions[0];
  groupHint.textContent = option && option.value !== "" ? option.dataset.description || "" : "";
}

// The row a group is drawn in, built with DOM calls, so its identifier is shown as text (#120).
function groupRow(id, identifier) {
  const row = document.createElement("tr");
  row.dataset.id = String(id);
  const cell = document.createElement("td");
  cell.className = "cell-mono cell-wrap";
  const link = document.createElement("a");
  link.className = "text-link";
  link.href = "/admin/groups/" + id + "/settings";
  link.textContent = identifier;
  cell.appendChild(link);
  const actions = document.createElement("td");
  actions.className = "cell-actions";
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "button button-sm";
  remove.dataset.listRemove = "";
  remove.textContent = groupsForm.dataset.removeLabel;
  const name = document.createElement("span");
  name.className = "sr-only";
  name.textContent = " " + identifier;
  remove.appendChild(name);
  actions.appendChild(remove);
  row.append(cell, actions);
  return row;
}

function addGroup() {
  const option = groupSelect.selectedOptions[0];
  if (!option || option.value === "") {
    refuseGroup(groupsForm.dataset.unchosen);
    return;
  }
  const id = Number(option.value);
  if (memberOf().includes(id)) {
    refuseGroup(groupsForm.dataset.duplicate);
    return;
  }
  clearGroupRefusal();
  groupRows.appendChild(groupRow(id, option.dataset.groupIdentifier));
  showGroupsEmpty();
  groupSelect.value = "";
  showGroupDescription();
  groupSelect.focus();
  groupAnnounce.textContent = groupsForm.dataset.added;
}

// removeGroup takes row out of the set, and puts the focus on the next row's Remove, or else the
// one before, or else the group field, so it is not lost with the button that had it.
function removeGroup(row) {
  const next = row.nextElementSibling || row.previousElementSibling;
  row.remove();
  showGroupsEmpty();
  if (next) {
    next.querySelector("[data-list-remove]").focus();
  } else {
    groupSelect.focus();
  }
  groupAnnounce.textContent = groupsForm.dataset.removed;
}

function saveGroups() {
  const body = {};
  body[groupsForm.dataset.listKey] = memberOf();
  body[groupsForm.dataset.expectedKey] = loadedGroupIds;
  sendAjaxRequest({
    url: groupsForm.dataset.saveUrl,
    method: "POST",
    bodyData: JSON.stringify(body),
    statusRegion: groupStatus,
    callback: function (result) {
      if (result.Success) {
        window.location.href = groupsForm.dataset.reloadUrl;
      }
    }
  });
}

groupSelect.addEventListener("change", function () {
  showGroupDescription();
  clearGroupRefusal();
});
groupsForm.querySelector("[data-group-add]").addEventListener("click", addGroup);
groupRows.addEventListener("click", function (event) {
  const remove = event.target.closest("[data-list-remove]");
  if (remove) {
    removeGroup(remove.closest("tr"));
  }
});
groupsForm.addEventListener("submit", function (event) {
  event.preventDefault();
  saveGroups();
});
// pageshow comes after the browser restores the form, on the first visit and on Back alike.
window.addEventListener("pageshow", showGroupDescription);
