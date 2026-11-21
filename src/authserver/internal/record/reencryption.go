package record

// StoredSecret names one stored secret by where it is held: its table, its column and its row's
// id. It never carries the value, so a report of one can be written where an operator reads it
// (#492 decision 5).
type StoredSecret struct {
	Table  string
	Column string
	ID     int64
}

// Reencryption is what one run of the re-encryption sweep did. A run that stopped early, cancelled
// or failed, answers what it did up to there, and a later run carries on from the data as it left
// it (#492 decision 4).
type Reencryption struct {
	// Reencrypted counts the values the sweep found under the previous data key and wrote under
	// the current one.
	Reencrypted int
	// AlreadyCurrent counts the values the sweep found under the current data key, which it left
	// as they were.
	AlreadyCurrent int
	// Unreadable counts the values neither data key opens, each left exactly as it is. The sweep
	// names each one to its caller as it reaches it, so a run holds no list of them.
	Unreadable int
}
