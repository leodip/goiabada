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

function getTrashCanMarkup(classStr, onclickStr, dataStr) {
  return "<button class='btn-sm btn btn-ghost " + classStr + "' onclick=\"" + onclickStr + "\" " + dataStr + ">" +  
  "<svg class='inline-block w-5 h-5 align-middle' xmlns='http://www.w3.org/2000/svg' viewBox='0 0 20 20' fill='currentColor'>" + 
      "<path fill-rule='evenodd' d='M8.75 1A2.75 2.75 0 006 3.75v.443c-.795.077-1.584.176-2.365.298a.75.75 0 10.23 1.482l.149-.022.841 10.518A2.75 2.75 0 007.596 19h4.807a2.75 2.75 0 002.742-2.53l.841-10.52.149.023a.75.75 0 00.23-1.482A41.03 41.03 0 0014 4.193V3.75A2.75 2.75 0 0011.25 1h-2.5zM10 4c.84 0 1.673.025 2.5.075V3.75c0-.69-.56-1.25-1.25-1.25h-2.5c-.69 0-1.25.56-1.25 1.25v.325C8.327 4.025 9.16 4 10 4zM8.58 7.72a.75.75 0 00-1.5.06l.3 7.5a.75.75 0 101.5-.06l-.3-7.5zm4.34.06a.75.75 0 10-1.5-.06l-.3 7.5a.75.75 0 101.5.06l.3-7.5z' clip-rule='evenodd' />" + 
  "</svg>" +
  "</button>";
}
