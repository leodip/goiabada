package record

import "time"

// RateLimitCounter is one shared rate-limit tier's count for one key in one window (#394). The
// credential-guessing tiers count here on PostgreSQL, MySQL and SQL Server, so every replica spends
// the same budget.
//
// There is no id: the digest and the window are the key. KeyHash is the lowercase hex SHA-256 of
// the tier name and the key, never the key itself. WindowStart is aligned to the Unix epoch, so
// every pod agrees where a window begins. Hits is the charges taken in that window: failures, and
// checks still in flight, since a reservation is charged before the credential is checked and
// refunded when it was right. ExpiresAt is two windows after WindowStart, when no rate reads the
// row any more.
type RateLimitCounter struct {
	KeyHash     string    `db:"key_hash"`
	WindowStart time.Time `db:"window_start"`
	Hits        int       `db:"hits"`
	ExpiresAt   time.Time `db:"expires_at"`
}
