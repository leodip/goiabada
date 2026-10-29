// introspection-resources.js is the behaviour of a client's Introspection tab: a resource is chosen,
// its description shown whole beneath the field, and Add lists it among the resources whose tokens
// the client may introspect; resources are removed in the page too, and Save sends the list whole,
// beside the list as the page drew it, so the server refuses a save from an outdated page rather
// than undo another administrator's change (#428). The form names the save's route and fields in
// its data set.
//
// Add with no resource chosen, or one in the list already, is refused at the field, which says why;
// a resource added or removed is announced, since the change shows only in the list. Save asks
// first where the form says so, through confirmChanges, then reloads the tab, which says the list
// was saved; a refusal is said in the tab's status region. A choice the browser restores, as on
// Back, shows its description.

const introspectionForm = document.getElementById("introspectionListForm");
const resourceSelect = introspectionForm.querySelector("[data-resource-select]");
const resourceError = introspectionForm.querySelector("[data-resource-error]");
const resourceHint = introspectionForm.querySelector("[data-resource-description]");
const resourceRows = introspectionForm.querySelector("[data-list-rows]");
const resourceRegion = introspectionForm.querySelector("[data-list-region]");
const resourceEmpty = introspectionForm.querySelector("[data-list-empty]");
const resourceAnnounce = introspectionForm.querySelector("[data-list-announce]");
const introspectionStatus = document.getElementById("introspectionListStatus");

// listedIds reads the list as the page shows it now, from its rows.
function listedIds() {
  return Array.from(resourceRows.querySelectorAll("tr")).map(function (row) {
    return Number(row.dataset.id);
  });
}

const loadedResourceIds = listedIds();

function showResourcesEmpty() {
  const empty = resourceRows.querySelector("tr") === null;
  resourceRegion.hidden = empty;
  resourceEmpty.hidden = !empty;
}

function refuseResource(message) {
  resourceError.textContent = message;
  resourceError.hidden = false;
  resourceSelect.setAttribute("aria-invalid", "true");
  resourceSelect.focus();
}

function clearResourceRefusal() {
  resourceError.textContent = "";
  resourceError.hidden = true;
  resourceSelect.removeAttribute("aria-invalid");
}

function showResourceDescription() {
  const option = resourceSelect.selectedOptions[0];
  resourceHint.textContent = option && option.value !== "" ? option.dataset.description || "" : "";
}

// The row a resource is drawn in, built with DOM calls, so its identifier is shown as text (#120).
function resourceRow(id, identifier) {
  const row = document.createElement("tr");
  row.dataset.id = String(id);
  const cell = document.createElement("td");
  cell.className = "cell-mono cell-wrap";
  const link = document.createElement("a");
  link.className = "text-link";
  link.href = "/admin/resources/" + id + "/settings";
  link.textContent = identifier;
  cell.appendChild(link);
  const actions = document.createElement("td");
  actions.className = "cell-actions";
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "button button-sm";
  remove.dataset.listRemove = "";
  remove.textContent = introspectionForm.dataset.removeLabel;
  const name = document.createElement("span");
  name.className = "sr-only";
  name.textContent = " " + identifier;
  remove.appendChild(name);
  actions.appendChild(remove);
  row.append(cell, actions);
  return row;
}

function addResource() {
  const option = resourceSelect.selectedOptions[0];
  if (!option || option.value === "") {
    refuseResource(introspectionForm.dataset.unchosen);
    return;
  }
  const id = Number(option.value);
  if (listedIds().includes(id)) {
    refuseResource(introspectionForm.dataset.duplicate);
    return;
  }
  clearResourceRefusal();
  resourceRows.appendChild(resourceRow(id, option.dataset.resourceIdentifier));
  showResourcesEmpty();
  resourceSelect.value = "";
  showResourceDescription();
  resourceSelect.focus();
  resourceAnnounce.textContent = introspectionForm.dataset.added;
}

// removeResource takes row out of the list, and puts the focus on the next row's Remove, or else
// the one before, or else the resource field, so it is not lost with the button that had it.
function removeResource(row) {
  const next = row.nextElementSibling || row.previousElementSibling;
  row.remove();
  showResourcesEmpty();
  if (next) {
    next.querySelector("[data-list-remove]").focus();
  } else {
    resourceSelect.focus();
  }
  resourceAnnounce.textContent = introspectionForm.dataset.removed;
}

function saveResources() {
  const body = {};
  body[introspectionForm.dataset.listKey] = listedIds();
  body[introspectionForm.dataset.expectedKey] = loadedResourceIds;
  sendAjaxRequest({
    url: introspectionForm.dataset.saveUrl,
    method: "POST",
    bodyData: JSON.stringify(body),
    statusRegion: introspectionStatus,
    callback: function (result) {
      if (result.Success) {
        window.location.href = introspectionForm.dataset.saveUrl;
      }
    }
  });
}

resourceSelect.addEventListener("change", function () {
  showResourceDescription();
  clearResourceRefusal();
});
introspectionForm.querySelector("[data-resource-add]").addEventListener("click", addResource);
resourceRows.addEventListener("click", function (event) {
  const remove = event.target.closest("[data-list-remove]");
  if (remove) {
    removeResource(remove.closest("tr"));
  }
});
introspectionForm.addEventListener("submit", function (event) {
  event.preventDefault();
  confirmChanges(introspectionForm, saveResources);
});
// pageshow comes after the browser restores the form, on the first visit and on Back alike.
window.addEventListener("pageshow", showResourceDescription);
