package models

import (
	"database/sql"
	"time"
)

// BrowserSession is one browser's session, held server side. The cookie the browser
// carries names this row with an opaque identifier and holds nothing else, so the
// session's contents never leave the deployment (#266).
type BrowserSession struct {
	Id        int64        `db:"id" fieldtag:"pk"`
	CreatedAt sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt sql.NullTime `db:"updated_at"`
	// Owner is the application the session belongs to, "authserver" or "adminconsole".
	// One table serves both, and every lookup is keyed on this column together with the
	// hash, so neither application can reach the other's rows.
	Owner string `db:"owner"`
	// SessionId is the plaintext identifier. It has a field so a caller can carry it
	// between generating it and putting it in the cookie, and `db:"-"` so it can never
	// reach a column: only its digest is stored, following the shape codes.Code
	// established for reset and activation codes (#112, #266).
	SessionId     string `db:"-"`
	SessionIdHash string `db:"session_id_hash"`
	// Data is the encrypted session contents. The storage layer holds ciphertext and
	// no key for it, so nothing here can read what a session contains.
	Data string `db:"data"`
	// LastAccessed is written lazily rather than on every request, so ordinary browsing
	// does not put a write in front of every page.
	LastAccessed time.Time `db:"last_accessed"`
	// ExpiresAt is when this session stops being usable, and it is a request-time rule
	// rather than a cleanup marker: every read and every conditional write requires
	// expires_at to be in the future, so an expired row is already absent to a caller
	// whether or not the reaper has run.
	ExpiresAt time.Time `db:"expires_at"`
}
