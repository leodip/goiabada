package dtos

type AdminClientAuthentication struct {
	ClientID         uint
	ClientIdentifier string
	IsPublic         bool
	ClientSecret     string
}
