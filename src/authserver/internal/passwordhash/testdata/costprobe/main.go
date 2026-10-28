// Command costprobe prints the bcrypt cost of a hash Hash writes and of the dummy DummyHash
// selects, as an ordinary binary outside go test sees them. TestCostOutsideGoTest builds it in
// the same build as its own, race or not, and expects the default cost from both (#691).
package main

import (
	"fmt"
	"os"

	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	hashed, err := passwordhash.Hash("any_password_here")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	hashCost, err := bcrypt.Cost([]byte(hashed))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	dummyCost, err := bcrypt.Cost([]byte(passwordhash.DummyHash()))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("%d %d\n", hashCost, dummyCost)
}
