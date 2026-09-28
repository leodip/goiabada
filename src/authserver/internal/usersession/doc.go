// Package usersession manages the auth server's user sessions, the user_sessions rows that record
// a signed-in user: Manager starts one when a ceremony completes, bumps it when a ceremony reuses
// it, and judges whether it may still be used. It is the one of three session packages that knows
// about users. core/sessionstore is the browser session store whose cookie names the user session,
// and internal/sessionbackend is where the auth server keeps that store's rows. The two session
// lifetimes and the client's max_age are parameters of HasValidUserSession rather than read from
// the request context (#433).
package usersession
