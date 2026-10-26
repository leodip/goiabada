//go:build race

package passwordhash

import (
	"flag"

	"golang.org/x/crypto/bcrypt"
)

// The bcrypt cost level this build uses, for the hashes Hash writes and for the dummy hash
// the enumeration-safe sign-in paths compare against (#691). Under the race detector one
// cost-10 bcrypt comparison takes close to half a second, and the unit tiers' rate-limiter
// tests spend most of their time comparing passwords: the slowest package raced for around
// nine minutes where the same tests take under one without the detector. bcrypt's rounds are
// pure computation that shares nothing between goroutines, so their number changes nothing
// the detector can see, while every code path still runs under it.
//
// So this build's dummy is the same string hashed at bcrypt.MinCost, and a run under go
// test -- the whole race tier -- hashes at bcrypt.MinCost too. A race build outside go
// test keeps hashing at bcrypt.DefaultCost, because a binary someone builds with -race to
// debug a deployment must still store the hashes that deployment compares, while its dummy
// stays the cost-4 one: that build is a debugging instrument (the release images build
// without cgo, which -race needs, so they cannot be race builds), and the timing its
// refusals give away is that debug binary's own.

// DummyHash is the dummy the enumeration-safe sign-in paths compare against in this build,
// at the cost the race tier needs: the hash was generated using bcrypt.MinCost (4) for the
// string "dummy_password_for_timing_safe_comparison", so the dummy comparison costs what
// a hash Hash produces costs under go test, rather than the default cost that dominates
// the race tier (#691). What the dummy is for -- the two callers, the two cases it keeps
// silent, the plaintext that signs no one in -- is documented on the !race declaration
// (#681).
const DummyHash = "$2a$04$qIL0aazYVE6kSZ9geNgU7ONkFdBQ8jm.W/0KDDkJZw5M0TbtgqyHS"

// raceBuildHashCost is the cost Hash uses when the gate below reports a run under go test.
const raceBuildHashCost = bcrypt.MinCost

// raceBuildTestRun reports whether this race build is running under go test: the test
// runner registers the flags it owns on the default flag set before any test runs, so
// finding one tells it without importing the test framework itself, which the
// refused-package table keeps out of a shipped binary (#331, #462).
func raceBuildTestRun() bool {
	return flag.Lookup("test.v") != nil
}
