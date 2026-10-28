//go:build race

package authflow

// The dummy hash the sign-in paths compare against in this build, written out so the test does
// not read it from the code it checks. A race build under go test compares against the
// cost-4 dummy, so this expectation also fails if a later change stops that run from
// selecting it (#691).
const testDummyHash = "$2a$04$qIL0aazYVE6kSZ9geNgU7ONkFdBQ8jm.W/0KDDkJZw5M0TbtgqyHS"
