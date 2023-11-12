package lib

import (
	"github.com/spf13/viper"
	"golang.org/x/exp/slog"
)

func GetBaseUrl() string {
	baseUrl := viper.GetString("BaseUrl")

	if len(baseUrl) == 0 {
		slog.Error("Environment variable GOIABADA_BASEURL is not set. This variable is essential for the system to operate correctly.")
		return baseUrl
	}

	return baseUrl
}
