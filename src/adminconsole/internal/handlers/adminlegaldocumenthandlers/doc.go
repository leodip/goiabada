// Package adminlegaldocumenthandlers serves the admin pages for legal documents (#622), under
// /admin/legal-documents: the list, a new document, each document's draft, which is edited beside
// a preview the auth server renders, its published versions, and retiring, restoring and deleting
// it. Every page reads and writes through the auth server's admin API, in its settings domain,
// with the administrator's token.
//
// A document is drafted, then published as a numbered version that never changes. Its kind is
// fixed at creation, and its short name, its public address, once it is first published. A
// document never published can be deleted; a published one can only be retired, and restored.
// The API decides each of these rules, and these pages say its refusals at the field they are
// about.
//
// A handler answers a page or JSON, never both, and passes an admin API failure to render's
// classifiers. HttpHelper is declared here rather than imported from the parent handlers package,
// and each handler names the API methods it calls in an unexported port beside it (#386, #440).
package adminlegaldocumenthandlers
