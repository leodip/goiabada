package bootstrap

import (
	"os"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/encryption"
)

// TestMain initializes the process cipher, which the seed encrypts the client secret and both
// private keys with, as main does before the database is opened (#83).
func TestMain(m *testing.M) {
	if err := encryption.InitDataCipher([]byte("0123456789abcdef0123456789abcdef")); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
