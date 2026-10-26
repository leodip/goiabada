//go:build !race

package passwordhash

import "golang.org/x/crypto/bcrypt"

// The cost level this build's tests owe Hash and DummyHash: without the race detector
// nothing may move off the default (#691).
const testHashCost = bcrypt.DefaultCost
