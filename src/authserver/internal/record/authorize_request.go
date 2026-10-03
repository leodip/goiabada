package record

import (
	"database/sql"
	"time"
)

// AuthorizeRequest is an authorization request a POST to /auth/authorize parked for the GET it is
// answered with (#246, #437). The row is written by the POST, which touches nothing of the
// browser's own session, and consumed by the GET, which carries the browser's cookie and runs the
// ceremony from what the row held.
type AuthorizeRequest struct {
	Id        int64        `db:"id" fieldtag:"pk"`
	CreatedAt sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt sql.NullTime `db:"updated_at"`
	// Handle is the plaintext handle. It has a field so a caller can carry it between generating it
	// and putting it in the redirect, and `db:"-"` so it can never reach a column: only its digest
	// is stored, following the shape browser sessions established (#266).
	Handle     string `db:"-"`
	HandleHash string `db:"handle_hash"`
	// RequestForm is the request's parameters, form encoded. It is not sealed: what it holds is
	// what the browser has just sent, and the handle that finds it is only ever stored as a digest.
	RequestForm string `db:"request_form"`
	// ExpiresAt is when the request stops being consumable, and it is a request-time rule rather
	// than a cleanup marker: the read requires expires_at to be in the future, so an expired row is
	// already absent to a caller whether or not the sweep has reached it.
	ExpiresAt time.Time `db:"expires_at"`
}
