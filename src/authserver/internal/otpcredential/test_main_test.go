package otpcredential

import (
	"fmt"
	"os"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/encryption"
)

func TestMain(m *testing.M) {
	// The same fixed key the handler packages use in theirs. Without it every setSecret in this
	// package fails, so Establish would return an error before opening a transaction and every
	// case below would pass on the cipher rather than on what it claims to be testing (#111
	// stage 4).
	if err := encryption.InitDataCipher([]byte("0123456789abcdef0123456789abcdef")); err != nil {
		fmt.Fprintf(os.Stderr, "encryption.InitDataCipher in TestMain: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
