package initialization

import (
	"fmt"
	"strings"
	"time"

	"log/slog"

	"github.com/leodip/goiabada/internal/lib"
	"github.com/spf13/viper"
)

func InitViper() {

	viper.SetEnvPrefix("GOIABADA")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	viper.SetDefault("AppName", "Goiabada")
	viper.SetDefault("Admin.Email", "admin@example.com")
	viper.SetDefault("Admin.Password", "changeme")

	if !lib.IsRunningInDocker() {
		// if not running in docker, use localhost as default host
		// otherwise we want this to be empty so that the server can listen on all network interfaces
		viper.SetDefault("Host", "localhost")
	}

	httpScheme := "http"
	if lib.IsHttpsEnabled() {
		viper.SetDefault("Port", "8443")
		httpScheme = "https"
	} else {
		viper.SetDefault("Port", "8080")
	}

	viper.SetDefault("BaseUrl", fmt.Sprintf("%s://%s:%s", httpScheme, viper.GetString("Host"), viper.GetString("Port")))
	viper.SetDefault("Issuer", viper.GetString("BaseUrl"))

	if len(viper.GetString("DB.Host")) == 0 {
		viper.SetDefault("DB.Type", "sqlite")
	} else {
		viper.SetDefault("DB.Type", "mysql")
		viper.SetDefault("DB.Host", "localhost")
		viper.SetDefault("DB.Port", "3306")
		viper.SetDefault("DB.Name", "goiabada")
		viper.SetDefault("DB.Username", "root")
	}

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
