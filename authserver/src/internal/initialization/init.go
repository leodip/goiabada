package initialization

import (
	"strings"
	"time"

	"log/slog"

	"github.com/leodip/goiabada/internal/lib"
	"github.com/spf13/viper"
)

func InitViper() {

	viper.SetDefault("DB.Type", "mysql")

	viper.SetEnvPrefix("GOIABADA")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	slog.Info("viper configuration initialized")
}

func InitTimeZones() {
	// trigger the load of timezones from OS (they will be cached)
	_ = lib.GetTimeZones()

	slog.Info("timezones loaded")
	slog.Info("current time zone is:" + time.Now().Location().String())
	slog.Info("current local time is:" + time.Now().String())
	slog.Info("current UTC time is:" + time.Now().UTC().String())
}
