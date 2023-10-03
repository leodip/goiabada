function focusOnFirstNonEmptyInput(formName) {
  var form = document.getElementById(formName);
  for (var i = 0; i < form.elements.length; i++) {
    var element = form.elements[i];
    if (
      (element.type === "text" || element.type === "password") &&
      element.value.trim() == ""
    ) {
      element.focus();
      break;
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
  if(btn1 && btn1callback) {
    btn1.onclick = null;
    btn1.onclick = btn1callback;
  }

  const btn2 = document.getElementById(id + "_btnModal2");
  if(btn2 && btn2callback) {
    btn2.onclick = null;
    btn2.onclick = btn2callback;
  }
  
  document.getElementById(id + "_modalDialog").showModal();
}
