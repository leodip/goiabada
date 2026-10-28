//go:build !race

package authflow

// The dummy hash the sign-in paths compare against in this build, written out so the test does
// not read it from the code it checks. Without the race detector the selection never leaves the
// default cost, so this is today's DummyHash value (#691).
const testDummyHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
