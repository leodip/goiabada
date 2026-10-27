//go:build race

package passwordhash

import "golang.org/x/crypto/bcrypt"

// The cost level this build's tests owe Hash and DummyHash: a race build under go test runs
// the tier at bcrypt's minimum cost, so bcrypt does not dominate it (#691).
const testHashCost = bcrypt.MinCost

// The build flags TestCostOutsideGoTest builds its probe with, so it runs in this build: a
// race build outside go test, the debug binary that must keep the default cost.
var probeBuildFlags = []string{"-race"}
