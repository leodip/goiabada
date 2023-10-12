package dtos

type AdminClient struct {
	ClientIdentifier         string
	ClientDescription        string
	Enabled                  bool
	ConsentRequired          bool
	IsPublic                 bool
	ClientSecret             string
	AuthorizationCodeEnabled bool
	ClientCredentialsEnabled bool
	RedirectUris             []string
}
