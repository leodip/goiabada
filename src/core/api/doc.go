// Package api is the wire contract of the auth server's admin, account and public settings APIs:
// the request and response bodies the auth server reads and writes and the admin console sends
// and decodes, and the few values both sides must spell alike. It is declarations and nothing
// else; the mapping from a persistence model to a response is the auth server's, in
// internal/apimapping, and nothing here imports a model (#350).
//
// One file per resource, each declaring that resource's requests beside its responses: users,
// groups, clients, resources and their permissions, settings, account (the self-service API),
// sessions (the user sessions an administrator lists, and the browser session endpoint the admin
// console keeps its own sessions behind), audit, and errors, which holds the two envelopes every
// resource answers with (#441).
package api
