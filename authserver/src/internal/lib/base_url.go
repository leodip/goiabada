package lib

import (
	"github.com/spf13/viper"
	"golang.org/x/exp/slog"
)

func GetBaseUrl() string {
	baseUrl := viper.GetString("BaseUrl")

	if len(baseUrl) == 0 {
		slog.Error("expecting BaseUrl to be set, but it's empty - please check config")
		return baseUrl
	}

	return baseUrl
}
