package adminsettingshandlers

type SettingsEmailGet struct {
	SMTPEnabled    bool
	SMTPHost       string
	SMTPPort       int
	SMTPUsername   string
	SMTPPassword   string
	SMTPEncryption string
	SMTPFromName   string
	SMTPFromEmail  string
}

type SettingsEmailPost struct {
	SMTPEnabled    bool
	SMTPHost       string
	SMTPPort       string
	SMTPUsername   string
	SMTPPassword   string
	SMTPEncryption string
	SMTPFromName   string
	SMTPFromEmail  string
}

type SettingsGeneral struct {
	AppName                                   string
	Issuer                                    string
	SelfRegistrationEnabled                   bool
	SelfRegistrationRequiresEmailVerification bool
	DynamicClientRegistrationEnabled          bool
	PasswordPolicy                            string
}

type SettingsKey struct {
	Id               int64
	CreatedAt        string
	State            string
	KeyIdentifier    string
	Type             string
	Algorithm        string
	PublicKeyASN1DER string
	PublicKeyPEM     string
	PublicKeyJWK     string
}

type SettingsSessionGet struct {
	UserSessionIdleTimeoutInSeconds int
	UserSessionMaxLifetimeInSeconds int
}

type SettingsSessionPost struct {
	UserSessionIdleTimeoutInSeconds string
	UserSessionMaxLifetimeInSeconds string
}

type SettingsTokenGet struct {
	TokenExpirationInSeconds                int
	RefreshTokenOfflineIdleTimeoutInSeconds int
	RefreshTokenOfflineMaxLifetimeInSeconds int
	IncludeOpenIDConnectClaimsInAccessToken bool
}

type SettingsTokenPost struct {
	TokenExpirationInSeconds                string
	RefreshTokenOfflineIdleTimeoutInSeconds string
	RefreshTokenOfflineMaxLifetimeInSeconds string
	IncludeOpenIDConnectClaimsInAccessToken bool
}

type SettingsUITheme struct {
	UITheme string
}
