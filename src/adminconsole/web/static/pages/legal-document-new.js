// legal-document-new.js is the new legal document page's behaviour: it suggests the document's
// short name from its title as the title is typed (#622 decision 5). The short name follows the
// title while it is empty or still the suggestion; once the person types a short name of their
// own it is left as they typed it, until they empty it again. The auth server decides what a
// short name may be, and the form says its refusal at the field.

// suggestShortName answers the short name a title suggests: its letters with their accents taken
// off, lowercased, its digits, every other run of characters as one hyphen, at most 64 characters,
// and no hyphen first or last, so a short name the auth server accepts as it is.
function suggestShortName(title) {
  return title
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+/, "")
    .slice(0, 64)
    .replace(/-+$/, "");
}

const newTitle = document.getElementById("title");
const newShortName = document.getElementById("shortName");

if (newTitle && newShortName) {
  let following = true;
  // A refused form, and one the browser restores, as on Back, is drawn with a short name that may
  // be the person's own: it follows the title only if it is empty or what the title suggests.
  const decide = function () {
    following = newShortName.value === "" || newShortName.value === suggestShortName(newTitle.value);
  };
  decide();
  window.addEventListener("pageshow", decide);

  newTitle.addEventListener("input", function () {
    if (following) {
      newShortName.value = suggestShortName(newTitle.value);
    }
  });
  newShortName.addEventListener("input", function () {
    following = newShortName.value === "";
  });
}
