package oauth

import (
	"os"
	"testing"

	"github.com/leodip/goiabada/core/config"
)

func TestMain(m *testing.M) {
	config.Init()
	code := m.Run()
	os.Exit(code)
}
