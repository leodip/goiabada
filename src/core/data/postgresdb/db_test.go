package postgresdb

import (
	"testing"
)

// TestAdvisoryLockKey pins what the comment on AdvisoryLockKey claims, because "stable by
// construction" is only worth saying if something checks it.
//
// The lock is what makes concurrent starts against an absent database safe, and it only works
// while every process racing for one database name computes the SAME key. A change to the
// namespace, the hash or the byte order would leave a redeployed instance taking a different
// lock from one already running, which is the unserialised behaviour back again and silent: the
// build stays green and the race only shows under concurrency against an absent database.
//
// Hence the literal. An assertion that merely recomputed the function would agree with any
// change to it.
func TestAdvisoryLockKey(t *testing.T) {
	const (
		name = "goiabada"
		want = int64(-3802063355692041455)
	)

	if got := AdvisoryLockKey(name); got != want {
		t.Errorf("AdvisoryLockKey(%q) = %d, want %d: the key is the identity two Goiabada "+
			"processes serialise on, so changing it stops a new instance serialising against a "+
			"running one (#293)", name, got, want)
	}

	if a, b := AdvisoryLockKey(name), AdvisoryLockKey(name); a != b {
		t.Errorf("AdvisoryLockKey(%q) is not deterministic: %d then %d", name, a, b)
	}

	// Different names take different locks, which is the point of keying by name at all:
	// pg_database.datname is compared byte-exact, so two differently named databases have no
	// reason to wait for each other.
	if a, b := AdvisoryLockKey(name), AdvisoryLockKey(name+"_other"); a == b {
		t.Errorf("AdvisoryLockKey collides for %q and %q, both %d", name, name+"_other", a)
	}

	// And case is a difference, not a fold. On PostgreSQL it genuinely is one, which is the
	// whole reason this key carries the name while SQL Server's resource cannot.
	if a, b := AdvisoryLockKey("goiabada"), AdvisoryLockKey("Goiabada"); a == b {
		t.Errorf("AdvisoryLockKey folds case: %q and %q both give %d, but pg_database.datname "+
			"compares byte-exact (#293)", "goiabada", "Goiabada", a)
	}
}
