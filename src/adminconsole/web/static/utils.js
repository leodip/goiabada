// utils.js

// t looks up a key in window.i18n (populated by the JSBootstrap server-side
// helper). Falls back to the key itself so missing entries are visible during
// development.
function t(key) {
  return (window.i18n && window.i18n[key]) || key;
}

// tFormat substitutes {{name}} placeholders in the catalog value with the
// supplied params. Plain string-replace — does NOT HTML-escape values, so
// don't pass untrusted data without escaping at the call site.
function tFormat(key, params) {
  let s = t(key);
  if (params) {
    for (const k in params) {
      s = s.split("{{" + k + "}}").join(String(params[k]));
    }
  }
  return s;
}

// escapeHtml renders a string as text in a place that expects markup. Callers pass
// literal markup to showModalDialog on purpose, so the escaping belongs at the one call
// site that forwards a server-supplied string rather than inside showModalDialog itself.
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

// dialogMarkups holds every message dialogMarkup and dialogMarkupFormat have built, so that
// showModalDialog can tell one from a string, and nothing but those two can make one.
const dialogMarkups = new WeakSet();

function sealDialogMarkup(html) {
  const markup = Object.freeze({ html: html });
  dialogMarkups.add(markup);
  return markup;
}

// dialogMarkup builds a dialog message that keeps its markup, an accent span or a line break, from
// the catalog: parts are catalog literals and values go between them, each escaped, so a value is
// always shown as text. A part is never data; TestDialogMessages_MarkupOnlyThroughTheBuilder holds
// every call's parts to an array of catalog literals (#120).
function dialogMarkup(parts, ...values) {
  if (!Array.isArray(parts) || parts.length !== values.length + 1) {
    throw new Error("dialogMarkup takes one more part than it takes arguments to escape");
  }
  let html = parts[0];
  for (let i = 0; i < values.length; i++) {
    html += escapeHtml(values[i]) + parts[i + 1];
  }
  return sealDialogMarkup(html);
}

// dialogMarkupFormat is dialogMarkup for a client-side catalog sentence: it substitutes the
// {{name}} placeholders of key's catalog value with params, each escaped, and keeps the sentence's
// own markup (#120).
function dialogMarkupFormat(key, params) {
  let html = t(key);
  for (const name in params) {
    html = html.split("{{" + name + "}}").join(escapeHtml(params[name]));
  }
  return sealDialogMarkup(html);
}

// showModalDialog parses message as HTML only when dialogMarkup or dialogMarkupFormat built it.
function showModalDialog(id, title, message, btn1callback, btn2callback) {
  document.getElementById(id + "_modalDialogTitle").innerText = title;
  const messageElement = document.getElementById(id + "_modalDialogMessage");
  if (dialogMarkups.has(message)) {
    messageElement.innerHTML = message.html;
  } else {
    messageElement.innerHTML = message;
  }

  const btn1 = document.getElementById(id + "_btnModal1");
  if (btn1 && btn1callback) {
    btn1.onclick = null;
    btn1.onclick = btn1callback;
  }

  const btn2 = document.getElementById(id + "_btnModal2");
  if (btn2 && btn2callback) {
    btn2.onclick = null;
    btn2.onclick = btn2callback;
  }

  document.getElementById(id + "_modalDialog").showModal();
}

// createIconButton returns a small ghost button holding one icon drawn from the path data in
// pathData, built with DOM calls so no value reaches an HTML parser. onclick is called with the
// click event and the button. Each entry of data is set through the button's data set, so a handler
// reads it back with elem.dataset (#120).
function createIconButton(pathData, evenOdd, onclick, data) {
  const svgNS = "http://www.w3.org/2000/svg";
  const button = document.createElement("button");
  button.className = "btn-sm btn btn-ghost";
  for (const [key, value] of Object.entries(data || {})) {
    button.dataset[key] = value;
  }
  button.onclick = function (event) {
    onclick(event, button);
  };

  const svg = document.createElementNS(svgNS, "svg");
  svg.setAttribute("class", "inline-block w-5 h-5 align-middle");
  svg.setAttribute("viewBox", "0 0 20 20");
  svg.setAttribute("fill", "currentColor");
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

function createTrashCanButton(onclick, data) {
  return createIconButton([
    "M8.75 1A2.75 2.75 0 006 3.75v.443c-.795.077-1.584.176-2.365.298a.75.75 0 10.23 1.482l.149-.022.841 10.518A2.75 2.75 0 007.596 19h4.807a2.75 2.75 0 002.742-2.53l.841-10.52.149.023a.75.75 0 00.23-1.482A41.03 41.03 0 0014 4.193V3.75A2.75 2.75 0 0011.25 1h-2.5zM10 4c.84 0 1.673.025 2.5.075V3.75c0-.69-.56-1.25-1.25-1.25h-2.5c-.69 0-1.25.56-1.25 1.25v.325C8.327 4.025 9.16 4 10 4zM8.58 7.72a.75.75 0 00-1.5.06l.3 7.5a.75.75 0 101.5-.06l-.3-7.5zm4.34.06a.75.75 0 10-1.5-.06l-.3 7.5a.75.75 0 101.5.06l.3-7.5z"
  ], true, onclick, data);
}

function createEditButton(onclick, data) {
  return createIconButton([
    "M5.433 13.917l1.262-3.155A4 4 0 017.58 9.42l6.92-6.918a2.121 2.121 0 013 3l-6.92 6.918c-.383.383-.84.685-1.343.886l-3.154 1.262a.5.5 0 01-.65-.65z",
    "M3.5 5.75c0-.69.56-1.25 1.25-1.25H10A.75.75 0 0010 3H4.75A2.75 2.75 0 002 5.75v9.5A2.75 2.75 0 004.75 18h9.5A2.75 2.75 0 0017 15.25V10a.75.75 0 00-1.5 0v5.25c0 .69-.56 1.25-1.25 1.25h-9.5c-.69 0-1.25-.56-1.25-1.25v-9.5z"
  ], false, onclick, data);
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

function sendAjaxRequest(props) {

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

    fetch(props.url, {
      method: props.method,
      headers: headers,
      body: props.bodyData,
    })
      .then((response) => {
        if (!response.ok) {

          if(response.status == 401) {
            setLoading(false);
            showModalDialog(
              props.modalId,
              t("js.error.session_expired_title"),
              t("js.error.session_expired_body")
            );
            return;
          }

          response.text().then((text) => {
            try {
              const err = JSON.parse(text);
              // The admin API refused the access token: say so, and sign out once the dialog
              // closes, by its button or by Escape alike.
              if (isSessionEnded(err)) {
                setLoading(false);
                showModalDialog(props.modalId, t("js.error.session_expired_title"),
                  escapeHtml(err.error_description));
                document.getElementById(props.modalId + "_modalDialog")
                  .addEventListener("close", goToSessionEnded, { once: true });
                return;
              }
              // The title says whose mistake it was. A 5xx is the server's, so it is
              // "Server error"; a 400, 404 or 409 is a rejected value, a stale record or
              // a conflict, and the sentence below already explains it, so the title is
              // the plain "Error" (#279).
              const title = response.status >= 500
                ? t("js.error.server_error_title")
                : t("js.error.error_title");
              // error_description can echo back what the user typed: handlers now
              // forward the API's 400 description verbatim so a validation failure is
              // readable, and showModalDialog assigns this to innerHTML (#122).
              showModalDialog(props.modalId, title, escapeHtml(err.error_description));
              setLoading(false);
            } catch (err) {
              showModalDialog(
                props.modalId,
                t("js.error.error_title"),
                tFormat("js.error.unexpected", { detail: response.status })
              );
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
          props.callback(result);
        }
      })
      .catch((err) => {
        showModalDialog(
          props.modalId,
          t("js.error.error_title"),
          tFormat("js.error.unexpected", { detail: err })
        );
      });
  } catch (err) {
    showModalDialog(
      props.modalId,
      t("js.error.error_title"),
      tFormat("js.error.unexpected", { detail: err })
    );
    setLoading(false);
  }
}
