package record

import "database/sql"

// PostLogoutRedirectURI is one of a client's sign-out redirect URIs: an address a sign-out may send
// the browser back to, as OpenID Connect RP-Initiated Logout 1.0 calls post_logout_redirect_uri. It
// is kept apart from the client's redirect URIs, so a sign-out landing page never becomes a place an
// authorization code can be delivered (#147). Its uri column is as wide as redirect_uris.uri, so
// RedirectURIMaxBytes and RedirectURIsMaxPerClient bound it too.
type PostLogoutRedirectURI struct {
	Id        int64        `db:"id" fieldtag:"pk"`
	CreatedAt sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	URI       string       `db:"uri"`
	ClientId  int64        `db:"client_id"`
}
