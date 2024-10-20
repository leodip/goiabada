package adminuserhandlers

import (
	"os"
	"testing"

	"github.com/leodip/goiabada/core/config"
)

func TestMain(m *testing.M) {
	config.Init("AdminConsole")
	code := m.Run()
	os.Exit(code)
}
