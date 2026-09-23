// Package apihandlers serves the auth server's two JSON APIs: the admin API under
// /api/v1/admin, which the admin console calls, and the account self-service API under
// /api/v1/account, which a signed-in user's own token reaches. The bearer token scopes each
// route requires are declared in routes.go, not here. Every handler answers JSON through the
// writers in api_common.go and never renders a page. The collaborators the handlers take are the
// ports in interfaces.go, and each handler's database port is declared beside the function
// taking it.
package apihandlers
