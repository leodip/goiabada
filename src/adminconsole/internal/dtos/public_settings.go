package dtos

type PublicSettingsResponse struct {
	AppName     string `json:"appName"`
	UITheme     string `json:"uiTheme"`
	SMTPEnabled bool   `json:"smtpEnabled"`
}
