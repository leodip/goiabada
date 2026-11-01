// turnstile-widget.js draws the Turnstile challenge's widget on a form that carries it, at the size
// that fits the form: flexible, as wide as the form, where the form is at least 300 pixels wide,
// the narrowest Cloudflare draws that size, and compact, 150 by 140, where it is narrower, as on a
// 320-pixel screen. The size is set before Cloudflare's script is loaded, which this script then
// loads, so the widget is drawn once, at that size. Cloudflare's script draws every element of
// class cf-turnstile with the data- attributes it carries.

// drawTurnstileWidgets sizes each widget on the page, then loads Cloudflare's script, whose address
// loader, this script's element, carries.
function drawTurnstileWidgets(loader) {
  const flexibleMinWidth = 300;
  document.querySelectorAll(".cf-turnstile").forEach(function (widget) {
    widget.dataset.size = widget.clientWidth >= flexibleMinWidth ? "flexible" : "compact";
  });

  const cloudflare = document.createElement("script");
  cloudflare.src = loader.dataset.widgetScript;
  cloudflare.async = true;
  document.head.appendChild(cloudflare);
}

// document.currentScript is this script's element only while it runs, so it is read here.
drawTurnstileWidgets(document.currentScript);
