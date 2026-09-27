package accounthandlers

import (
	"fmt"
	"os"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/encryption"
)

func TestMain(m *testing.M) {
	config.Init()
	if err := encryption.InitDataCipher([]byte("0123456789abcdef0123456789abcdef")); err != nil {
		fmt.Fprintf(os.Stderr, "encryption.InitDataCipher in TestMain: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	os.Exit(code)
}
