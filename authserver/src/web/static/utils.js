function focusOnFirstNonEmptyInput(formName) {
  var form = document.getElementById(formName);
  if (form) {
    for (var i = 0; i < form.elements.length; i++) {
      var element = form.elements[i];
      if ((element.type === "text" || element.type === "password") && element.value.trim() == "") {
        element.focus();
        break;
      }
    }
  }
}

function findClosestAncestor(element, tagName) {
  let currentElement = element;

  while (currentElement !== document) {
    if (currentElement.tagName === tagName) {
      return currentElement;
    }
    currentElement = currentElement.parentNode;
  }
  return null;
}

function showModalDialog(id, title, message, btn1callback, btn2callback) {
  document.getElementById(id + "_modalDialogTitle").innerText = title;
  document.getElementById(id + "_modalDialogMessage").innerHTML = message;

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

function getTrashCanMarkup(classStr, onclickStr, dataStr) {
  return (
    "<button class='btn-sm btn btn-ghost " + classStr + "' onclick=\"" + onclickStr + '" ' + dataStr + ">" +
    "<svg class='inline-block w-5 h-5 align-middle' xmlns='http://www.w3.org/2000/svg' viewBox='0 0 20 20' fill='currentColor'>" +
    "<path fill-rule='evenodd' d='M8.75 1A2.75 2.75 0 006 3.75v.443c-.795.077-1.584.176-2.365.298a.75.75 0 10.23 1.482l.149-.022.841 10.518A2.75 2.75 0 007.596 19h4.807a2.75 2.75 0 002.742-2.53l.841-10.52.149.023a.75.75 0 00.23-1.482A41.03 41.03 0 0014 4.193V3.75A2.75 2.75 0 0011.25 1h-2.5zM10 4c.84 0 1.673.025 2.5.075V3.75c0-.69-.56-1.25-1.25-1.25h-2.5c-.69 0-1.25.56-1.25 1.25v.325C8.327 4.025 9.16 4 10 4zM8.58 7.72a.75.75 0 00-1.5.06l.3 7.5a.75.75 0 101.5-.06l-.3-7.5zm4.34.06a.75.75 0 10-1.5-.06l-.3 7.5a.75.75 0 101.5.06l.3-7.5z' clip-rule='evenodd' />" +
    "</svg>" +
    "</button>"
  );
}

function getEditMarkup(classStr, onclickStr, dataStr) {
  return (
    "<button class='btn-sm btn btn-ghost " + classStr + "' onclick=\"" + onclickStr +  '" ' + dataStr + ">" +
    "<svg class='inline-block w-5 h-5 align-middle' xmlns='http://www.w3.org/2000/svg' viewBox='0 0 20 20' fill='currentColor'>" +
    '<path d="M5.433 13.917l1.262-3.155A4 4 0 017.58 9.42l6.92-6.918a2.121 2.121 0 013 3l-6.92 6.918c-.383.383-.84.685-1.343.886l-3.154 1.262a.5.5 0 01-.65-.65z" />' +
    '<path d="M3.5 5.75c0-.69.56-1.25 1.25-1.25H10A.75.75 0 0010 3H4.75A2.75 2.75 0 002 5.75v9.5A2.75 2.75 0 004.75 18h9.5A2.75 2.75 0 0017 15.25V10a.75.75 0 00-1.5 0v5.25c0 .69-.56 1.25-1.25 1.25h-9.5c-.69 0-1.25-.56-1.25-1.25v-9.5z" />' +
    "</svg>" +
    "</button>"
  );
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
          response.text().then((text) => {
            try {
              const err = JSON.parse(text);
              showModalDialog(props.modalId, "Server error", err.error_description);
              setLoading(false);
            } catch (err) {
              showModalDialog(
                props.modalId,
                "Error",
                "An unexpected error has occurred: <span class='text-error'>" +
                  response.status +
                  "</span>. Please refresh the page and try again."
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
          if (result.RequiresAuth) {
            showModalDialog(
              props.modalId,
              "Session expired",
              "Your authentication session has expired. To continue, please refresh the page and re-authenticate to start a new session."
            );
          } else {
            props.callback(result);
          }
        }
      })
      .catch((err) => {
        showModalDialog(
          props.modalId,
          "Error",
          "An unexpected error has occurred: <span class='text-error'>" + err + "</span>. Please refresh the page and try again."
        );
      });
  } catch (err) {
    showModalDialog(
      props.modalId,
      "Error",
      "An unexpected error has occurred: <span class='text-error'>" + err + "</span>. Please refresh the page and try again."
    );
    setLoading(false);
  }
}
