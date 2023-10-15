package dtos

type AdminClientRedirectUris struct {
	ClientID                 uint
	ClientIdentifier         string
	AuthorizationCodeEnabled bool
	RedirectUris             map[uint]string
}
