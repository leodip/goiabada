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
