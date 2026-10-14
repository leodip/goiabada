// utils.js

function showModalDialog(id, title, message, btn1callback, btn2callback) {
  document.getElementById(id + "_modalDialogTitle").innerText = title;
  document.getElementById(id + "_modalDialogMessage").textContent = message;

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

// submitOnce is a form's onsubmit handler for a form that must be sent once: the password and the
// two code forms. The first submission goes, and the form's buttons are disabled, so a double click
// or a repeated Enter sends no second one; implicit submission does not go through a disabled
// default button. A second submission reaching the server after the first rotated the browser
// session away would meet the "no longer active" page (#579). A page the browser restores from its
// back-forward cache gets its buttons back, so the form can be sent again from there.
function submitOnce(form) {
  if (form.dataset.submitted === "true") {
    return false;
  }
  form.dataset.submitted = "true";
  form.querySelectorAll("button").forEach(function (button) {
    button.disabled = true;
  });
  window.addEventListener("pageshow", function (event) {
    if (event.persisted) {
      delete form.dataset.submitted;
      form.querySelectorAll("button").forEach(function (button) {
        button.disabled = false;
      });
    }
  }, { once: true });
  return true;
}
