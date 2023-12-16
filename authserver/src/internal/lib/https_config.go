package lib

import "github.com/spf13/viper"

func IsHttpsEnabled() bool {
	httpsEnabled := true

	certFile := viper.GetString("CertFile")
	keyFile := viper.GetString("KeyFile")

	if len(certFile) == 0 || len(keyFile) == 0 {
		httpsEnabled = false
	}

	return httpsEnabled
}
