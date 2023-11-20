package initialization

import (
	"fmt"
	"os"
	"strings"
	"time"

	"log/slog"

	"github.com/leodip/goiabada/internal/lib"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

func InitViper() {

	viper.SetDefault("StaticDir", "./static")
	viper.SetDefault("TemplateDir", "./template")

	viper.SetConfigName("config")
	viper.SetConfigType("json")

	// possible locations for config file
	viper.AddConfigPath("./configs")
	viper.AddConfigPath("../../configs") // for integration tests

	viper.SetEnvPrefix("GOIABADA")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// Config file was found but another error was produced
			slog.Error(errors.Wrap(err, "unable to initialize configuration - make sure a config.json file exists and has content").Error())
			os.Exit(1)
		}
	}

	slog.Info("viper configuration initialized")
	if len(viper.ConfigFileUsed()) > 0 {
		slog.Info(fmt.Sprintf("viper config file used: %v", viper.ConfigFileUsed()))
	}
}

func InitTimeZones() {
	// trigger the load of timezones from OS (they will be cached)
	_ = lib.GetTimeZones()

	slog.Info("timezones loaded")
	slog.Info("current time zone is:" + time.Now().Location().String())
	slog.Info("current local time is:" + time.Now().String())
	slog.Info("current UTC time is:" + time.Now().UTC().String())
}
