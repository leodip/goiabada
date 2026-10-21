// form-post.js is the form_post response page's one behaviour: it submits the page's form as soon as
// the document is parsed, which delivers the authorization response to the client. Without
// JavaScript the page's own button does.

document.querySelectorAll("form[data-auto-submit]").forEach(function (form) {
  form.submit();
});
