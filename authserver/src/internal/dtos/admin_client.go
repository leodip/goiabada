package dtos

type AdminClientPermission struct {
	ID    uint
	Scope string
}

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
	Permissions              []AdminClientPermission
}
