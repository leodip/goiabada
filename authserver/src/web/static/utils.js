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

function showModalDialog(title, message, closeCallback) {
  document.getElementById("modalDialogTitle").innerText = title;
  document.getElementById("modalDialogMessage").innerHTML = message;

  if(closeCallback) {
    const btnClose = document.getElementById("btnCloseModalDialog");
    btnClose.onclick = null;
    btnClose.onclick = closeCallback;
  }

  document.getElementById("modalDialog").showModal();
}
