package lib

import (
	"log/slog"

	"github.com/spf13/viper"
)

func GetBaseUrl() string {
	baseUrl := viper.GetString("BaseUrl")

	if len(baseUrl) == 0 {
		slog.Error("Environment variable GOIABADA_BASEURL is not set. This variable is essential for the system to operate correctly.")
		return baseUrl
	}

	return baseUrl
}
