// utils.js

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
