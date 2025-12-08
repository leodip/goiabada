package config

const (
	// Listen port
	WebAppPort = "3000"

	// OAuth2/OIDC Client settings
	// Create a client in Goiabada admin console with these settings:
	// - Redirect URI: http://localhost:3000/callback
	// - Post-logout redirect URI: http://localhost:3000/
	ClientID     = "test-client"
	ClientSecret = "89lXx1vBOfBbWsJzCfIM0vUyvfX1EF7LjmGJM5u29bLqxAjZfanXE-wSYsv2"

	// Auth server endpoints (configured for devcontainer on port 19090)
	IssuerURL          = "http://localhost:19090"
	AuthURL            = "http://localhost:19090/auth/authorize"
	TokenURL           = "http://localhost:19090/auth/token"
	UserInfoURL        = "http://localhost:19090/userinfo"
	JWKSURL            = "http://localhost:19090/certs"
	EndSessionEndpoint = "http://localhost:19090/auth/logout"

	// Callback URLs
	RedirectURL           = "http://localhost:3000/callback"
	PostLogoutRedirectURL = "http://localhost:3000/"

	// Session keys (32 bytes each)
	// In production, these should be randomly generated and stored securely
	SessionAuthKey       = "your-32-byte-auth-key-here-12345"
	SessionEncryptionKey = "your-32-byte-encrypt-key-here-00"
)

type AppConfig struct {
	ClientID              string
	ClientSecret          string
	IssuerURL             string
	AuthURL               string
	TokenURL              string
	UserInfoURL           string
	JWKSURL               string
	EndSessionEndpoint    string
	RedirectURL           string
	PostLogoutRedirectURL string
}

func GetAppConfig() *AppConfig {
	return &AppConfig{
		ClientID:              ClientID,
		ClientSecret:          ClientSecret,
		IssuerURL:             IssuerURL,
		AuthURL:               AuthURL,
		TokenURL:              TokenURL,
		UserInfoURL:           UserInfoURL,
		JWKSURL:               JWKSURL,
		EndSessionEndpoint:    EndSessionEndpoint,
		RedirectURL:           RedirectURL,
		PostLogoutRedirectURL: PostLogoutRedirectURL,
	}
}
