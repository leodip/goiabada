// user-search.js is the behaviour of a page that finds users to add to something: the search field
// asks as the person types, after a pause, and Enter asks at once, the form never submitting
// natively. The answer is drawn in the results table, each user with an Add button posting to the
// form's data-add-url with the user's id, which row-actions.js runs, or with a tag where the user
// is in already, which the answer's data-member-key field says.
//
// Only the latest request's answer is drawn, or its failure said, and only while the field still
// holds the words it asked about: a change to the field ends the search under way at once, not when
// the pause runs out and the next one starts, so a slow answer never draws users for words the field
// no longer holds. The change also clears the status region, whose last word was about the results
// it replaces. At most data-max-rows users are drawn, and a note, data-truncated, says when the
// search found more.

const searchForm = document.getElementById("userSearchForm");
const searchInput = searchForm.querySelector("input[type=search]");
const searchStatus = document.getElementById("row-actions-status");
const resultsRegion = document.querySelector("[data-results-region]");
const resultsRows = document.querySelector("[data-results-rows]");
const resultsNote = document.querySelector("[data-results-note]");

let searchRequest = 0;

function nameOf(user) {
  return [user.GivenName, user.MiddleName, user.FamilyName].filter(function (part) {
    return part;
  }).join(" ");
}

// The row a user is drawn in, built with DOM calls, so every value is shown as text (#120).
function resultRow(user) {
  const row = document.createElement("tr");

  const who = document.createElement("td");
  who.className = "cell-wrap sm:whitespace-nowrap";
  const link = document.createElement("a");
  link.className = "text-link";
  link.href = "/admin/users/" + Number(user.Id) + "/details";
  link.textContent = user.Email;
  who.appendChild(link);
  const name = nameOf(user);
  if (name || user.Username) {
    const secondary = document.createElement("span");
    secondary.className = "cell-secondary";
    secondary.textContent = [name, user.Username].filter(function (part) {
      return part;
    }).join(" · ");
    who.appendChild(secondary);
  }

  const subject = document.createElement("td");
  subject.className = "cell-mono";
  subject.dataset.label = searchForm.dataset.subjectLabel;
  subject.textContent = user.Subject;

  const action = document.createElement("td");
  action.className = "cell-actions";
  if (user[searchForm.dataset.memberKey]) {
    const tag = document.createElement("span");
    tag.className = "tag tag-positive";
    tag.textContent = searchForm.dataset.memberLabel;
    action.appendChild(tag);
  } else {
    const add = document.createElement("button");
    add.type = "button";
    add.className = "button button-sm";
    add.dataset.actionUrl = searchForm.dataset.addUrl.replace("{userId}", String(Number(user.Id)));
    add.dataset.actionBody = "{}";
    add.dataset.done = searchForm.dataset.added;
    add.dataset.doneLabel = searchForm.dataset.memberLabel;
    add.dataset.doneTone = "positive";
    add.textContent = searchForm.dataset.addLabel;
    const hidden = document.createElement("span");
    hidden.className = "sr-only";
    hidden.textContent = " " + user.Email;
    add.appendChild(hidden);
    action.appendChild(add);
  }

  row.append(who, subject, action);
  return row;
}

function showResults(users) {
  const max = Number(searchForm.dataset.maxRows);
  const shown = users.slice(0, max);
  resultsRows.replaceChildren(...shown.map(resultRow));
  resultsRegion.hidden = shown.length === 0;
  if (searchInput.value.trim() === "") {
    resultsNote.textContent = searchForm.dataset.prompt;
  } else if (shown.length === 0) {
    resultsNote.textContent = searchForm.dataset.none;
  } else if (users.length > max) {
    resultsNote.textContent = searchForm.dataset.truncated;
  } else {
    resultsNote.textContent = "";
  }
  resultsNote.hidden = resultsNote.textContent === "";
}

function search() {
  const query = searchInput.value.trim();
  const request = ++searchRequest;
  if (query === "") {
    showResults([]);
    return;
  }
  sendAjaxRequest({
    url: searchForm.dataset.searchUrl + "?" + new URLSearchParams({ query: query }),
    method: "GET",
    bodyData: null,
    statusRegion: searchStatus,
    current: function () {
      return request === searchRequest && searchInput.value.trim() === query;
    },
    callback: function (result) {
      showResults(result.Users || []);
    }
  });
}

const searchSoon = debounce(search, 400);

searchInput.addEventListener("input", function () {
  searchRequest++;
  searchStatus.replaceChildren();
  if (searchInput.value.trim() === "") {
    showResults([]);
  }
  searchSoon();
});
searchForm.addEventListener("submit", function (event) {
  event.preventDefault();
  search();
});
// pageshow comes after the browser restores the field, on the first visit and on Back alike, so
// the results follow a search it restored.
window.addEventListener("pageshow", function () {
  if (searchInput.value.trim() !== "") {
    search();
  }
});
