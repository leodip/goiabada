package dtos

type AdminClientOAuth2Flows struct {
	ClientID                 uint
	ClientIdentifier         string
	IsPublic                 bool
	AuthorizationCodeEnabled bool
	ClientCredentialsEnabled bool
}
