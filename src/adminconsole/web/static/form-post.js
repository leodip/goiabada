// form-post.js is the sign-out redirect page's one behaviour: it submits the page's form as soon as
// the document is parsed, which carries the sign-out to the auth server in a request body. Without
// JavaScript the page's own button does.

document.querySelectorAll("form[data-auto-submit]").forEach(function (form) {
  form.submit();
});
