package security

type JwtInfo struct {
	TokenResponse TokenResponse

	AccessToken  *JwtToken
	IdToken      *JwtToken
	RefreshToken *JwtToken
}
