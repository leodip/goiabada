package handlers

import "github.com/leodip/goiabada/core/config"

func GetProfileURL() string {
	return config.GetAdminConsole().BaseURL + "/account/profile"
}
