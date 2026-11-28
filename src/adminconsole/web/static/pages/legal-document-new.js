// legal-document-new.js is the new legal document page's behaviour: it suggests the document's
// short name from its title as the title is typed (#622 decision 5). The short name follows the
// title while it is empty or still the suggestion; once the person types a short name of their
// own it is left as they typed it, until they empty it again. The auth server decides what a
// short name may be, and the form says its refusal at the field.

// latinLetters writes each lower-case letter of Russian, and Polish ł, in Latin letters (#666
// decision 8): ъ and ь are left out, and ё is e. A letter of another alphabet has no entry.
const latinLetters = {
  а: "a", б: "b", в: "v", г: "g", д: "d", е: "e", ё: "e", ж: "zh", з: "z", и: "i", й: "y",
  к: "k", л: "l", м: "m", н: "n", о: "o", п: "p", р: "r", с: "s", т: "t", у: "u", ф: "f",
  х: "kh", ц: "ts", ч: "ch", ш: "sh", щ: "shch", ъ: "", ы: "y", ь: "", э: "e", ю: "yu", я: "ya",
  ł: "l",
};

// suggestShortName answers the short name a title suggests: its Russian letters and ł written in
// Latin letters, its other letters with their accents taken off, lowercased, its digits, every
// other run of characters as one hyphen, at most 64 characters, and no hyphen first or last, so a
// short name the auth server accepts as it is. The title is composed first and written in Latin
// letters before the accents go, so й is y, not the и its accent leaves, however it is spelled.
function suggestShortName(title) {
  return title
    .normalize("NFC")
    .replace(/[а-яёА-ЯЁłŁ]/g, function (letter) {
      return latinLetters[letter.toLowerCase()];
    })
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
