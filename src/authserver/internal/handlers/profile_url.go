package handlers

import "github.com/leodip/goiabada/authserver/internal/config"

func GetProfileURL() string {
	return config.GetAdminConsole().BaseURL + "/account/profile"
}
