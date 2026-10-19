// utils.js is the admin console's shared page behaviour, loaded by both layouts before any page's
// own script.

// i18nTable holds the client-side strings, keyed by catalog key: the JSON data block #js-i18n that
// both layouts write from JSBootstrap. It is read on first use rather than when this file loads,
// so the order of the two elements in the page does not matter.
let i18nTable = null;

// t looks up a key among the client-side strings. It falls back to the key itself, so a missing
// entry shows as its key rather than as nothing.
function t(key) {
  if (i18nTable === null) {
    const block = document.getElementById("js-i18n");
    try {
      i18nTable = block ? JSON.parse(block.textContent) : {};
    } catch (err) {
      i18nTable = {};
    }
  }
  return i18nTable[key] || key;
}

// tFormat substitutes {{name}} placeholders in the catalog value with the
// supplied params. Plain string-replace — does NOT HTML-escape values, so its
// result is text: show it as text, or use dialogMarkupFormat for a dialog.
function tFormat(key, params) {
  let s = t(key);
  if (params) {
    for (const k in params) {
      s = s.split("{{" + k + "}}").join(String(params[k]));
    }
  }
  return s;
}

// escapeHtml renders a string as text in a place that expects markup. dialogMarkup and
// dialogMarkupFormat call it on every value they are given, because theirs is the one result
// showModalDialog parses as HTML; a plain message is shown as text and is never escaped first,
// or its entities would show as typed. Nothing else should need it: put data into the page as
// text instead (#120).
//
// The ampersand has to be replaced first, or the entities produced by the later
// replacements get their own ampersands escaped.
function escapeHtml(str) {
  return String(str)
    .split("&").join("&amp;")
    .split("<").join("&lt;")
    .split(">").join("&gt;")
    .split('"').join("&quot;")
    .split("'").join("&#39;");
}

// The error code the console answers an AJAX request with when the admin API refused its access
// token, and the route that then signs the administrator out and says why on the home page. The
// code is HandleAPIErrorJSON's sessionEndedCode and the path its sessionEndedPath; a drift test in
// internal/handlers holds the three to each other. Every fetch site here and in image-upload.js
// keys on the code rather than on the 403 it arrives with, so no other 403 signs anybody out (#427).
const SESSION_ENDED_CODE = "session_ended";
const SESSION_ENDED_PATH = "/auth/session-ended";

function isSessionEnded(err) {
  return err !== null && typeof err === "object" && err.error === SESSION_ENDED_CODE;
}

function goToSessionEnded() {
  window.location.assign(SESSION_ENDED_PATH);
}

// submitSignOut ends the administrator's session as the sign-out confirmation's own button does:
// a form posted to /auth/logout, which the origin check guards and passes as same-origin. A page
// whose own dialog has already confirmed ending the current session calls it rather than
// navigating to /auth/logout, whose GET only asks again (#411).
function submitSignOut() {
  const form = document.createElement("form");
  form.method = "post";
  form.action = "/auth/logout";
  document.body.appendChild(form);
  form.submit();
}

// withPageLanguage names the catalog this page rendered from, which the layout publishes as
// data-catalog-lang, as ui_locales on a request the page sends. The console resolves each request's
// language afresh, and ui_locales is the explicit intent neither the browser's Accept-Language nor
// the profile's locale overrides, so a refusal shown in this page's dialog, the API's or the
// console's own, is in the page's language (#559 decisions 3 and 7). Every fetch site here and in
// image-upload.js sends its URL through it, and a drift test in internal/render holds them to it.
function withPageLanguage(url) {
  const lang = document.documentElement.dataset.catalogLang;
  if (!lang) {
    return url;
  }
  const target = new URL(url, window.location.href);
  target.searchParams.set("ui_locales", lang);
  if (target.origin !== window.location.origin) {
    return target.href;
  }
  return target.pathname + target.search + target.hash;
}

// The dialog's markup boundary. showModalDialog parses a message as HTML only when dialogMarkup or
// dialogMarkupFormat built it, and shows any other message as text, so a value reaching it by any
// route is never parsed (#120). What marks a message as built, the registry and the function that
// adds to it, is private to this closure: a page reaches the HTML branch through the two builders,
// which escape every value, and through nothing else. TestUtilsJS_DialogMarkupBrandIsPrivate holds
// the closure to exporting these three and nothing more.
const { dialogMarkup, dialogMarkupFormat, showModalDialog } = (function () {
  const built = new WeakSet();

  function seal(html) {
    const markup = Object.freeze({ html: html });
    built.add(markup);
    return markup;
  }

  // dialogMarkup builds a dialog message that keeps its markup, an accent span or a line break,
  // from the catalog: parts are catalog literals and values go between them, each escaped, so a
  // value is always shown as text. A part is never data; TestDialogMessages_MarkupOnlyThroughTheBuilder
  // holds every call's parts to an array of catalog literals (#120).
  function dialogMarkup(parts, ...values) {
    if (!Array.isArray(parts) || parts.length !== values.length + 1) {
      throw new Error("dialogMarkup takes one more part than it takes arguments to escape");
    }
    let html = parts[0];
    for (let i = 0; i < values.length; i++) {
      html += escapeHtml(values[i]) + parts[i + 1];
    }
    return seal(html);
  }

  // dialogMarkupFormat is dialogMarkup for a client-side catalog sentence: it substitutes the
  // {{name}} placeholders of key's catalog value with params, each escaped, and keeps the
  // sentence's own markup (#120).
  function dialogMarkupFormat(key, params) {
    let html = t(key);
    for (const name in params) {
      html = html.split("{{" + name + "}}").join(escapeHtml(params[name]));
    }
    return seal(html);
  }

  // showModalDialog opens the dialog id with title and message. btn1callback runs when its first
  // button is clicked (Close, No or Cancel) and btn2callback when its second is (Yes or OK). A
  // message that is a list of sentences is shown as a list, one item each, and a list of one as
  // that sentence; each is text, built with DOM calls.
  function showModalDialog(id, title, message, btn1callback, btn2callback) {
    const dialog = document.getElementById(id + "_modalDialog");
    document.getElementById(id + "_modalDialogTitle").innerText = title;
    const messageElement = document.getElementById(id + "_modalDialogMessage");
    if (built.has(message)) {
      messageElement.innerHTML = message.html;
    } else if (Array.isArray(message) && message.length > 1) {
      const list = document.createElement("ul");
      message.forEach(function (sentence) {
        const item = document.createElement("li");
        item.textContent = sentence;
        list.appendChild(item);
      });
      messageElement.replaceChildren(list);
    } else if (Array.isArray(message)) {
      messageElement.textContent = message[0];
    } else {
      messageElement.textContent = message;
    }

    // A button's answer. The buttons sit in a form whose method is dialog, which closes the
    // dialog after the click's handler has run, and with it any question that handler asked:
    // the second confirmation of a chain was closed by the click that answered the first, and
    // its save dropped unasked. So the answer prevents the form's default, closes the dialog
    // itself, and only then runs the callback, which therefore finds the dialog closed and the
    // focus restored (#562). Escape closes the dialog without an answer, as before.
    function answer(callback) {
      return function (event) {
        event.preventDefault();
        dialog.close();
        if (callback) {
          callback(event);
        }
      };
    }

    // Every call sets both buttons, so a button given no callback just closes the dialog
    // rather than running the one a previous call left on it (#562).
    const btn1 = document.getElementById(id + "_btnModal1");
    if (btn1) {
      btn1.onclick = answer(btn1callback);
    }

    const btn2 = document.getElementById(id + "_btnModal2");
    if (btn2) {
      btn2.onclick = answer(btn2callback);
    }

    dialog.showModal();
  }

  return { dialogMarkup, dialogMarkupFormat, showModalDialog };
})();

// createIconButton returns a small ghost button holding one icon drawn from the path data in
// pathData, built with DOM calls so no value reaches an HTML parser. onclick is called with the
// click event and the button. Each entry of data is set through the button's data set, so a handler
// reads it back with elem.dataset (#120).
//
// The button has no text, so label is its name: written as its aria-label and its title, through
// setAttribute, and naming what it does and to which row, such as "Remove redirect URI " + uri. The
// icon is hidden from assistive technology, which would otherwise read it as an unnamed image. And
// it is a plain button, so inside a form it does only what onclick says and never submits it (#562).
function createIconButton(pathData, evenOdd, label, onclick, data) {
  const svgNS = "http://www.w3.org/2000/svg";
  const button = document.createElement("button");
  button.type = "button";
  button.className = "button button-quiet button-sm button-icon";
  button.setAttribute("aria-label", label);
  button.setAttribute("title", label);
  for (const [key, value] of Object.entries(data || {})) {
    button.dataset[key] = value;
  }
  button.onclick = function (event) {
    onclick(event, button);
  };

  const svg = document.createElementNS(svgNS, "svg");
  svg.setAttribute("viewBox", "0 0 20 20");
  svg.setAttribute("fill", "currentColor");
  svg.setAttribute("aria-hidden", "true");
  pathData.forEach(function (d) {
    const path = document.createElementNS(svgNS, "path");
    if (evenOdd) {
      path.setAttribute("fill-rule", "evenodd");
      path.setAttribute("clip-rule", "evenodd");
    }
    path.setAttribute("d", d);
    svg.appendChild(path);
  });
  button.appendChild(svg);
  return button;
}

// The icon each tone of notice shows, as ui.css's notice draws it in the templates.
const NOTICE_ICONS = {
  positive: "M10 18a8 8 0 1 0 0-16 8 8 0 0 0 0 16Zm3.857-9.809a.75.75 0 0 0-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 1 0-1.06 1.061l2.5 2.5a.75.75 0 0 0 1.137-.089l4-5.5Z",
  caution: "M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495ZM10 5a.75.75 0 0 1 .75.75v3.5a.75.75 0 0 1-1.5 0v-3.5A.75.75 0 0 1 10 5Zm0 9a1 1 0 1 0 0-2 1 1 0 0 0 0 2Z",
  danger: "M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0Zm-8-5a.75.75 0 0 1 .75.75v4.5a.75.75 0 0 1-1.5 0v-4.5A.75.75 0 0 1 10 5Zm0 10a1 1 0 1 0 0-2 1 1 0 0 0 0 2Z",
  note: "M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0Zm-7-4a1 1 0 1 1-2 0 1 1 0 0 1 2 0ZM9 9a.75.75 0 0 0 0 1.5h.253a.25.25 0 0 1 .244.304l-.459 2.066A1.75 1.75 0 0 0 10.747 15H11a.75.75 0 0 0 0-1.5h-.253a.25.25 0 0 1-.244-.304l.459-2.066A1.75 1.75 0 0 0 9.253 9H9Z"
};

// showNotice puts a notice of tone, "positive", "caution", "danger" or "note", saying text, in
// region, in place of whatever it held. region is a live region the page draws empty, such as a
// div with role="status", so the notice is announced as it appears; a script's answer to an action
// goes there rather than into a dialog. The text is shown as text, and the notice is built with DOM
// calls, so no value reaches an HTML parser (#120).
function showNotice(region, tone, text) {
  const svgNS = "http://www.w3.org/2000/svg";
  const notice = document.createElement("div");
  notice.className = "notice notice-" + tone;

  const svg = document.createElementNS(svgNS, "svg");
  svg.setAttribute("viewBox", "0 0 20 20");
  svg.setAttribute("fill", "currentColor");
  svg.setAttribute("aria-hidden", "true");
  const path = document.createElementNS(svgNS, "path");
  path.setAttribute("fill-rule", "evenodd");
  path.setAttribute("clip-rule", "evenodd");
  path.setAttribute("d", NOTICE_ICONS[tone]);
  svg.appendChild(path);
  notice.appendChild(svg);

  const message = document.createElement("p");
  message.textContent = text;
  notice.appendChild(message);

  region.replaceChildren(notice);
}

// setUpCopyButtons gives each button marked data-copy-target the copy of the text of the element it
// names, or of its value when it is a field, for a secret a person would otherwise type again, such
// as an authenticator key or a client secret, and says so for a moment on itself and in the status
// element data-copy-status names. It stays hidden where the browser cannot write to the clipboard,
// where the text is still there to select. Where the browser has the clipboard but refuses the
// write, as a denied permission does, it selects the text instead and says so, with
// data-copy-failed-label on itself and data-copy-failed-status in the status element. The auth
// server's utils.js does the same for its pages.
function setUpCopyButtons() {
  document.querySelectorAll("button[data-copy-target]").forEach(function (button) {
    const source = document.getElementById(button.dataset.copyTarget);
    const status = document.getElementById(button.dataset.copyStatus);
    const label = button.querySelector("span");
    if (!source || !label || !navigator.clipboard) {
      return;
    }
    const isField = source instanceof HTMLInputElement;
    const idle = label.textContent;
    let timer = 0;
    const say = function (text, announcement) {
      label.textContent = text || idle;
      if (status) {
        status.textContent = announcement || "";
      }
      clearTimeout(timer);
      timer = setTimeout(function () {
        label.textContent = idle;
        if (status) {
          status.textContent = "";
        }
      }, 2000);
    };
    button.hidden = false;
    button.addEventListener("click", function () {
      navigator.clipboard.writeText((isField ? source.value : source.textContent).trim()).then(function () {
        say(button.dataset.copiedLabel, button.dataset.copiedLabel);
      }, function () {
        const selection = window.getSelection();
        if (isField) {
          source.select();
        } else if (selection) {
          selection.selectAllChildren(source);
        }
        say(button.dataset.copyFailedLabel, button.dataset.copyFailedStatus);
      });
    });
  });
}

// setUpSearchableSelects turns each select marked data-searchable, a long list such as the time
// zones, into a combobox: a field that filters the select's options by any part of their text as
// the person types, accents and case aside, and the matches in a list below it, the WAI-ARIA
// editable combobox with list autocomplete. The arrow keys move through the matches, Enter or a
// click chooses one, Escape closes the list and puts back the choice, and leaving the field keeps
// the option its text names or else puts back the choice too; an empty field chooses the select's
// empty option, whose text becomes the field's placeholder. The select stays in the form, hidden,
// and holds the value it posts; the field takes its id, so the label names it, and its
// aria-invalid, aria-describedby and autofocus. Without JavaScript the select is what the page shows.
function setUpSearchableSelects() {
  document.querySelectorAll("select[data-searchable]").forEach(makeSearchable);
}

function makeSearchable(select) {
  const fold = function (text) {
    return text.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase();
  };
  const id = select.id;
  const listId = id + "-options";
  const label = document.querySelector('label[for="' + id + '"]');
  if (label && !label.id) {
    label.id = id + "-label";
  }

  const combobox = document.createElement("div");
  combobox.className = "combobox";
  const input = document.createElement("input");
  input.type = "text";
  input.className = "control combobox-input";
  input.autocomplete = "off";
  input.spellcheck = false;
  input.setAttribute("role", "combobox");
  input.setAttribute("aria-autocomplete", "list");
  input.setAttribute("aria-expanded", "false");
  input.setAttribute("aria-controls", listId);
  if (select.hasAttribute("aria-invalid")) {
    input.setAttribute("aria-invalid", select.getAttribute("aria-invalid"));
  }
  if (select.hasAttribute("aria-describedby")) {
    input.setAttribute("aria-describedby", select.getAttribute("aria-describedby"));
  }

  const popup = document.createElement("div");
  popup.className = "combobox-popup";
  popup.hidden = true;
  const list = document.createElement("ul");
  list.id = listId;
  list.setAttribute("role", "listbox");
  if (label) {
    list.setAttribute("aria-labelledby", label.id);
  }
  const empty = document.createElement("p");
  empty.className = "combobox-empty";
  empty.textContent = t("js.combobox.no_matches");
  empty.hidden = true;
  const status = document.createElement("span");
  status.className = "sr-only";
  status.setAttribute("role", "status");

  const entries = Array.from(select.options, function (option, index) {
    const item = document.createElement("li");
    item.id = listId + "-" + index;
    item.className = "combobox-option";
    item.setAttribute("role", "option");
    item.textContent = option.textContent.trim();
    list.appendChild(item);
    return { option: option, item: item, key: fold(item.textContent) };
  });
  const blank = entries.find(function (entry) {
    return entry.option.value === "";
  });
  if (blank) {
    input.placeholder = blank.item.textContent;
  }

  let shown = entries;
  let active = -1;
  // A press that began in the list and has not ended in a choice. On a touch screen the list
  // cannot always keep the focus in the field, so the blur such a press causes is not the person
  // leaving the field.
  let pressInList = false;

  function chosen() {
    return entries.find(function (entry) {
      return entry.option.selected;
    });
  }

  function showChoice() {
    const entry = chosen();
    input.value = entry && entry !== blank ? entry.item.textContent : "";
  }

  function setActive(index) {
    if (active >= 0 && shown[active]) {
      shown[active].item.removeAttribute("aria-selected");
    }
    active = index;
    if (active >= 0) {
      shown[active].item.setAttribute("aria-selected", "true");
      shown[active].item.scrollIntoView({ block: "nearest" });
      input.setAttribute("aria-activedescendant", shown[active].item.id);
    } else {
      input.removeAttribute("aria-activedescendant");
    }
  }

  function filter() {
    setActive(-1);
    const query = fold(input.value.trim());
    shown = entries.filter(function (entry) {
      const match = query === "" || entry.key.includes(query);
      entry.item.hidden = !match;
      entry.item.classList.toggle("combobox-option-chosen", entry.option.selected);
      return match;
    });
    empty.hidden = shown.length > 0;
    status.textContent = shown.length === 1 ? t("js.combobox.one_result")
      : tFormat("js.combobox.results", { count: shown.length });
  }

  // place opens the list below the field, or above it when there is little room below and more
  // above, and caps its height at the room on that side within the visible part of the page,
  // which on a phone leaves out the on-screen keyboard.
  function place() {
    const viewport = window.visualViewport;
    const top = viewport ? viewport.offsetTop : 0;
    const height = viewport ? viewport.height : window.innerHeight;
    const box = input.getBoundingClientRect();
    const below = top + height - box.bottom;
    const above = box.top - top;
    const up = below < 192 && above > below;
    popup.classList.toggle("combobox-popup-up", up);
    popup.style.maxHeight = Math.max(96, Math.min(256, (up ? above : below) - 12)) + "px";
  }

  function open() {
    popup.hidden = false;
    input.setAttribute("aria-expanded", "true");
    filter();
    place();
  }

  function close() {
    setActive(-1);
    popup.hidden = true;
    input.setAttribute("aria-expanded", "false");
    status.textContent = "";
  }

  function choose(entry) {
    if (!entry.option.selected) {
      select.value = entry.option.value;
      select.dispatchEvent(new Event("change", { bubbles: true }));
    }
    showChoice();
    close();
  }

  // commit keeps the option the field's text names, the empty one when the field is empty, and
  // otherwise puts the choice back, and closes the list.
  function commit() {
    const text = fold(input.value.trim());
    const named = text === "" ? blank : entries.find(function (entry) {
      return entry.key === text;
    });
    if (named) {
      choose(named);
    } else {
      showChoice();
      close();
    }
  }

  input.addEventListener("input", open);
  input.addEventListener("click", function () {
    if (popup.hidden) {
      open();
    }
  });
  input.addEventListener("keydown", function (event) {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      if (popup.hidden) {
        open();
      }
      if (shown.length > 0 && active < 0) {
        // From the field, down reaches the first match and up the last.
        setActive(event.key === "ArrowDown" ? 0 : shown.length - 1);
      } else if (shown.length > 0) {
        const step = event.key === "ArrowDown" ? 1 : -1;
        setActive((active + step + shown.length) % shown.length);
      }
    } else if (event.key === "Enter" && !popup.hidden) {
      event.preventDefault();
      const entry = active >= 0 ? shown[active] : shown[0];
      if (entry) {
        choose(entry);
      }
    } else if (event.key === "Escape" && !popup.hidden) {
      event.preventDefault();
      showChoice();
      close();
    }
  });
  input.addEventListener("blur", function () {
    if (!pressInList) {
      commit();
    }
  });

  // A press on the list keeps the focus in the field where the browser lets it, and a tap chooses
  // on the click that ends it. A finger that scrolls the list instead is cancelled and chooses
  // nothing.
  popup.addEventListener("pointerdown", function () {
    pressInList = true;
  });
  popup.addEventListener("pointerup", function () {
    setTimeout(function () {
      pressInList = false;
    }, 400);
  });
  popup.addEventListener("pointercancel", function () {
    pressInList = false;
  });
  popup.addEventListener("mousedown", function (event) {
    event.preventDefault();
  });
  list.addEventListener("click", function (event) {
    pressInList = false;
    const entry = entries.find(function (candidate) {
      return candidate.item === event.target.closest(".combobox-option");
    });
    if (entry) {
      choose(entry);
    }
  });
  // A press anywhere else, on a touch screen too, where it does not always blur the field.
  document.addEventListener("pointerdown", function (event) {
    if (!popup.hidden && !combobox.contains(event.target)) {
      commit();
    }
  });
  // The room around the field changes as the page scrolls, and as a phone's keyboard opens.
  const replace = function () {
    if (!popup.hidden) {
      place();
    }
  };
  window.addEventListener("scroll", replace, { passive: true });
  window.addEventListener("resize", replace);
  if (window.visualViewport) {
    window.visualViewport.addEventListener("resize", replace);
  }

  const hadFocus = document.activeElement === select || select.autofocus;
  select.id = id + "-select";
  select.hidden = true;
  input.id = id;
  popup.append(list, empty);
  combobox.append(input, popup, status);
  select.after(combobox);
  showChoice();
  // A page reached again through the browser's history can have the select's choice put back
  // after this has run, without a change event, so the field would name one option while the
  // form posts another. The field shows the select's choice again whenever the page is shown and
  // whenever the select changes.
  window.addEventListener("pageshow", showChoice);
  select.addEventListener("change", showChoice);
  if (hadFocus) {
    input.focus();
  }
}

function createTrashCanButton(label, onclick, data) {
  return createIconButton([
    "M8.75 1A2.75 2.75 0 006 3.75v.443c-.795.077-1.584.176-2.365.298a.75.75 0 10.23 1.482l.149-.022.841 10.518A2.75 2.75 0 007.596 19h4.807a2.75 2.75 0 002.742-2.53l.841-10.52.149.023a.75.75 0 00.23-1.482A41.03 41.03 0 0014 4.193V3.75A2.75 2.75 0 0011.25 1h-2.5zM10 4c.84 0 1.673.025 2.5.075V3.75c0-.69-.56-1.25-1.25-1.25h-2.5c-.69 0-1.25.56-1.25 1.25v.325C8.327 4.025 9.16 4 10 4zM8.58 7.72a.75.75 0 00-1.5.06l.3 7.5a.75.75 0 101.5-.06l-.3-7.5zm4.34.06a.75.75 0 10-1.5-.06l-.3 7.5a.75.75 0 101.5.06l.3-7.5z"
  ], true, label, onclick, data);
}

function createEditButton(label, onclick, data) {
  return createIconButton([
    "M5.433 13.917l1.262-3.155A4 4 0 017.58 9.42l6.92-6.918a2.121 2.121 0 013 3l-6.92 6.918c-.383.383-.84.685-1.343.886l-3.154 1.262a.5.5 0 01-.65-.65z",
    "M3.5 5.75c0-.69.56-1.25 1.25-1.25H10A.75.75 0 0010 3H4.75A2.75 2.75 0 002 5.75v9.5A2.75 2.75 0 004.75 18h9.5A2.75 2.75 0 0017 15.25V10a.75.75 0 00-1.5 0v5.25c0 .69-.56 1.25-1.25 1.25h-9.5c-.69 0-1.25-.56-1.25-1.25v-9.5z"
  ], false, label, onclick, data);
}

// describeSeconds reads a number of seconds typed into a field as a duration a person reads, such
// as "2 hours, 30 minutes", in the page's language. messages carries the sentences the page gives
// for a value that is not a whole number of seconds and for one too long to be meant, the form's
// data-duration-invalid and data-duration-too-long, and, where zero means something other than no
// time at all, such as the global setting, data-duration-zero, followed by the global setting's
// own duration where data-duration-global gives it, as "Uses the global setting (1 hour)".
function describeSeconds(value, messages) {
  const text = String(value).trim();
  if (!/^[0-9]+$/.test(text)) {
    return messages.durationInvalid;
  }
  const seconds = Number(text);
  if (seconds === 0 && messages.durationZero) {
    if (/^[0-9]+$/.test(messages.durationGlobal || "")) {
      return messages.durationZero + " (" + humanSeconds(Number(messages.durationGlobal)) + ")";
    }
    return messages.durationZero;
  }
  // About five years.
  if (seconds > 160000000) {
    return messages.durationTooLong;
  }
  return humanSeconds(seconds);
}

// humanSeconds says a number of seconds as a duration, in the page's language.
function humanSeconds(seconds) {
  const language = (document.documentElement.lang || "en").toLowerCase().split("-")[0];
  return humanizeDuration(seconds * 1000, {
    units: ["d", "h", "m", "s"],
    language: language,
    fallbacks: ["en"]
  });
}

// setUpDurations writes, under each duration field, the number of seconds typed as a duration a
// person reads, as the value changes and as the browser restores it: into each element marked
// data-duration-for, naming the field, with the sentences describeSeconds takes from the field's
// form, and the element's own data-duration-global.
function setUpDurations() {
  document.querySelectorAll("[data-duration-for]").forEach(function (output) {
    const input = document.getElementById(output.dataset.durationFor);
    if (!input || !input.form) {
      return;
    }
    const messages = Object.assign({}, input.form.dataset, output.dataset);
    const update = function () {
      output.textContent = describeSeconds(input.value, messages);
    };
    input.addEventListener("input", debounce(update, 300));
    // pageshow comes after the browser restores the form, as on Back, which fires no input.
    window.addEventListener("pageshow", update);
    update();
  });
}

// changesToConfirm lists what a save of form changes that its page asks about first: the sentence,
// data-confirm, of each control whose change it names, then the form's data-confirm-always, which
// every save of it asks. A field names a change when its value differs from the value stored when
// the page was drawn, data-stored-value, unless none was stored, since nothing then changes; a
// checkbox or a radio when it is now checked, or now unchecked, as data-confirm-when says, and was
// not when the page was drawn, as data-stored-checked says. A control in a hidden part of the form
// names none, since the save does not take what it holds.
function changesToConfirm(form) {
  const changes = [];
  form.querySelectorAll("[data-confirm]").forEach(function (control) {
    if (control.closest("[hidden]")) {
      return;
    }
    let changed;
    if (control.type === "checkbox" || control.type === "radio") {
      const stored = control.dataset.storedChecked === "true";
      changed = control.dataset.confirmWhen === "unchecked" ? stored && !control.checked : !stored && control.checked;
    } else {
      const stored = control.dataset.storedValue || "";
      changed = stored !== "" && control.value.trim() !== stored;
    }
    if (changed) {
      changes.push(control.dataset.confirm);
    }
  });
  if (form.dataset.confirmAlways) {
    changes.push(form.dataset.confirmAlways);
  }
  return changes;
}

// confirmChanges runs save at once when changesToConfirm finds nothing to ask about form, and
// otherwise asks first, every change in one question, in the confirm_change dialog the form's
// data-confirm-dialog names, titled data-confirm-title, and runs save if the answer is its action.
function confirmChanges(form, save) {
  const changes = changesToConfirm(form);
  if (changes.length === 0) {
    save();
    return;
  }
  showModalDialog(form.dataset.confirmDialog, form.dataset.confirmTitle, changes, null, save);
}

// setUpSaveConfirmations makes each form posted by the browser, method="post", that is marked
// data-confirm-dialog ask through confirmChanges before it is sent. A save with nothing to ask
// about is sent as it is; one the dialog asks about is sent again from its answer, since a browser
// ignores requestSubmit while the submit event it would fire is still being handled. A form a
// script saves calls confirmChanges itself.
function setUpSaveConfirmations() {
  document.querySelectorAll("form[method=post][data-confirm-dialog]").forEach(function (form) {
    let confirmed = false;
    form.addEventListener("submit", function (event) {
      if (confirmed || changesToConfirm(form).length === 0) {
        return;
      }
      event.preventDefault();
      const submitter = event.submitter;
      confirmChanges(form, function () {
        confirmed = true;
        form.requestSubmit(submitter);
      });
    });
  });
}

const debounce = (func, wait) => {
  let timeout;

  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };

    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
};

// sendAjaxRequest sends a JSON request to the console and hands a success's answer to
// props.callback. A failure is said in the dialog props.modalId names, or, on a page that answers
// in a status region, the one props.statusRegion holds, as a notice, the way that page says its
// successes; there an access token the admin API refused signs out at once, as the image upload
// does, since the home page then says why. A page that may stop wanting the answer, having asked
// again meanwhile, gives props.current, and neither the failure nor the answer of a request it no
// longer wants is shown; props.finished is told, once, that the request is over, however it ended.
function sendAjaxRequest(props) {

  const stale = () => typeof props.current === "function" && !props.current();
  let over = false;
  const finish = () => {
    if (!over) {
      over = true;
      if (props.finished) {
        props.finished();
      }
    }
  };

  // fail says why the request failed: title and message in the dialog, message alone in a notice.
  const fail = (title, message) => {
    finish();
    if (stale()) {
      return;
    }
    if (props.statusRegion) {
      showNotice(props.statusRegion, "danger", message);
    } else {
      showModalDialog(props.modalId, title, message);
    }
  };

  // failUnexpected says that the request failed in a way the console did not answer.
  const failUnexpected = (detail) => {
    finish();
    if (stale()) {
      return;
    }
    if (props.statusRegion) {
      showNotice(props.statusRegion, "danger", tFormat("js.error.unexpected_text", { detail: detail }));
    } else {
      showModalDialog(props.modalId, t("js.error.error_title"),
        dialogMarkupFormat("js.error.unexpected", { detail: detail }));
    }
  };

  let setLoading = (isLoading) => {
    if (!props.loadingElement) {
      return;
    }

    if (isLoading) {
      // prevent multiple clicks
      if (props.loadingElement.dataset.loading == "true") {
        return;
      }
      props.loadingClasses.map((v) => props.loadingElement.classList.add(v));
      props.loadingElement.classList.remove("hidden");
      props.loadingElement.classList.add("inline-block");
      props.loadingElement.dataset.loading = "true";

    } else {
      props.loadingClasses.map((v) => props.loadingElement.classList.remove(v));
      props.loadingElement.classList.remove("inline-block");
      props.loadingElement.classList.add("hidden");
      props.loadingElement.dataset.loading = "false";
    }
  };

  try {

    setLoading(true);

    let headers = {
      "Content-Type": "application/json; charset=UTF-8",
      "Accept": "application/json",
      "X-Requested-With": "XMLHttpRequest"
    };

    if (document.getElementsByName("gorilla.csrf.Token").length > 0) {
      headers["X-CSRF-Token"] = document.getElementsByName("gorilla.csrf.Token")[0].value;
    }

    fetch(withPageLanguage(props.url), {
      method: props.method,
      headers: headers,
      body: props.bodyData,
    })
      .then((response) => {
        if (!response.ok) {

          if(response.status == 401) {
            setLoading(false);
            fail(t("js.error.session_expired_title"), t("js.error.session_expired_body"));
            return;
          }

          response.text().then((text) => {
            try {
              const err = JSON.parse(text);
              // The admin API refused the access token: say so, and sign out once the dialog
              // closes, by its button or by Escape alike.
              if (isSessionEnded(err)) {
                setLoading(false);
                finish();
                if (props.statusRegion) {
                  goToSessionEnded();
                  return;
                }
                showModalDialog(props.modalId, t("js.error.session_expired_title"),
                  err.error_description);
                document.getElementById(props.modalId + "_modalDialog")
                  .addEventListener("close", goToSessionEnded, { once: true });
                return;
              }
              // The title says whose mistake it was. A 5xx is the server's, so it is
              // "Server error"; a 400, 404, 409 or 429 is a rejected value, a stale record,
              // a conflict or too many attempts, and the sentence below already explains
              // it, so the title is the plain "Error" (#279, #562).
              const title = response.status >= 500
                ? t("js.error.server_error_title")
                : t("js.error.error_title");
              // error_description can echo back what the user typed: handlers now
              // forward the API's 400 description verbatim so a validation failure is
              // readable (#122). It goes to the dialog as a plain message, or to a notice,
              // each shown as text, so it is not escaped first (#120).
              fail(title, err.error_description);
              setLoading(false);
            } catch (err) {
              failUnexpected(response.status);
              setLoading(false);
            }
          });
        } else {
          setLoading(false);
          return response.json();
        }
      })
      .then((result) => {
        if (result !== undefined) {
          finish();
          if (!stale()) {
            props.callback(result);
          }
        }
      })
      .catch((err) => {
        failUnexpected(err);
      });
  } catch (err) {
    failUnexpected(err);
    setLoading(false);
  }
}
