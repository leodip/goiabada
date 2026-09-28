package models

import (
	"database/sql"
	"time"
)

type UserSessionClient struct {
	Id        int64        `db:"id" fieldtag:"pk"`
	CreatedAt sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt sql.NullTime `db:"updated_at"`
	// Both keys are tagged dont-update because nothing reassigns an association's session
	// or its client: the row is created when a session first reaches a client and deleted
	// with the session. The tag is not hygiene. SQL Server re-checks a foreign key
	// whenever its column appears in an UPDATE's SET list, even with an unchanged value,
	// taking a shared lock on the parent row, and BumpUserSession writes EVERY association
	// the session has rather than only the one the ceremony is for. So a bump on a session
	// associated with clients A and B, running for A, held A's row shared and the session
	// row and then asked for B's, while a deletion of B held B exclusively and was waiting
	// for that session. Removing the lock is the fix rather than ordering it: a lock no
	// statement names is one no reader of that code can be expected to order (#139).
	UserSessionId int64     `db:"user_session_id" fieldtag:"dont-update"`
	ClientId      int64     `db:"client_id" fieldtag:"dont-update"`
	Client        Client    `db:"-"`
	Started       time.Time `db:"started"`
	LastAccessed  time.Time `db:"last_accessed"`
}
