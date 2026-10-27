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
// So a run under go test -- the whole race tier -- hashes at bcrypt.MinCost and compares
// refusals against the same dummy string hashed at bcrypt.MinCost. A race build outside go
// test keeps both at today's values: a binary someone builds with -race to debug a
// deployment must still store the hashes that deployment compares, and its refusals must
// still cost what a wrong password costs, so they say nothing about which accounts exist
// (#681).

// raceBuildDummyHash is the dummy DummyHash returns when the gate below reports a run under
// go test, at the cost the race tier needs: the hash was generated using bcrypt.MinCost (4)
// for the string "dummy_password_for_timing_safe_comparison", so the dummy comparison costs
// what a hash Hash produces costs under go test, rather than the default cost that dominates
// the race tier (#691).
const raceBuildDummyHash = "$2a$04$qIL0aazYVE6kSZ9geNgU7ONkFdBQ8jm.W/0KDDkJZw5M0TbtgqyHS"

// raceBuildHashCost is the cost Hash uses when the gate below reports a run under go test.
const raceBuildHashCost = bcrypt.MinCost

// raceBuildTestRun reports whether this race build is running under go test: the test
// runner registers the flags it owns on the default flag set before any test runs, so
// finding one tells it without importing the test framework itself, which the
// refused-package table keeps out of a shipped binary (#331, #462).
func raceBuildTestRun() bool {
	return flag.Lookup("test.v") != nil
}
