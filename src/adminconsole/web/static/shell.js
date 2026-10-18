// shell.js is the behaviour of the console's page shell, menu_layout.html: the menu button that
// opens the sidebar as a panel on narrow screens, and the user menu in the header. Both are
// disclosures: a button whose aria-expanded says whether what it controls is shown.

// The sidebar panel. While it is open the rest of the page is inert, so neither the keyboard nor a
// screen reader reaches what is behind it; Escape, the close button and a click on the backdrop
// close it, and focus goes back to the menu button. On a wide screen the sidebar is always shown
// and the panel never opens.
function setUpSidebar() {
  const sidebar = document.getElementById("app-sidebar");
  const openButton = document.querySelector("[data-app-menu-open]");
  const closeButton = document.querySelector("[data-app-menu-close]");
  const backdrop = document.querySelector("[data-app-backdrop]");
  const body = document.querySelector(".app-body");
  const wide = window.matchMedia("(min-width: 64rem)");
  if (!sidebar || !openButton || !body) {
    return;
  }

  function setOpen(open, restoreFocus) {
    sidebar.dataset.open = open ? "true" : "false";
    openButton.setAttribute("aria-expanded", open ? "true" : "false");
    if (backdrop) {
      backdrop.hidden = !open;
    }
    body.inert = open;
    if (open) {
      const first = closeButton || sidebar.querySelector("a, button");
      if (first) {
        first.focus();
      }
    } else if (restoreFocus) {
      openButton.focus();
    }
  }

  openButton.addEventListener("click", function () {
    setOpen(true, false);
  });
  if (closeButton) {
    closeButton.addEventListener("click", function () {
      setOpen(false, true);
    });
  }
  if (backdrop) {
    backdrop.addEventListener("click", function () {
      setOpen(false, true);
    });
  }
  sidebar.addEventListener("keydown", function (event) {
    if (event.key === "Escape" && sidebar.dataset.open === "true") {
      setOpen(false, true);
    }
  });
  // Crossing the width either way forgets the panel's state, so the sidebar settles where the new
  // width puts it without sliding.
  wide.addEventListener("change", function () {
    if (sidebar.dataset.open === "true") {
      setOpen(false, false);
    }
    delete sidebar.dataset.open;
  });
}

// The user menu. A click outside it, Escape, or focus moving out of it closes it.
function setUpUserMenu() {
  const button = document.querySelector("[data-user-menu-button]");
  if (!button) {
    return;
  }
  const panel = document.getElementById(button.getAttribute("aria-controls"));
  const menu = button.parentElement;

  function setOpen(open) {
    button.setAttribute("aria-expanded", open ? "true" : "false");
    panel.hidden = !open;
  }

  button.addEventListener("click", function () {
    setOpen(panel.hidden);
  });
  document.addEventListener("click", function (event) {
    if (!panel.hidden && !menu.contains(event.target)) {
      setOpen(false);
    }
  });
  menu.addEventListener("keydown", function (event) {
    if (event.key === "Escape" && !panel.hidden) {
      setOpen(false);
      button.focus();
    }
  });
  menu.addEventListener("focusout", function (event) {
    if (!panel.hidden && event.relatedTarget && !menu.contains(event.relatedTarget)) {
      setOpen(false);
    }
  });
}

setUpSidebar();
setUpUserMenu();
