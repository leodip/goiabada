package dtos

// PublicSettingsResponse mirrors the auth server's dtos.PublicSettingsResponse
// field for field. The two modules do not share a package, so nothing in the
// build checks that they agree: a field added on one side and forgotten on the
// other decodes to its zero value here, silently.
type PublicSettingsResponse struct {
	AppName     string `json:"appName"`
	UITheme     string `json:"uiTheme"`
	SMTPEnabled bool   `json:"smtpEnabled"`
	Issuer      string `json:"issuer"`
}
