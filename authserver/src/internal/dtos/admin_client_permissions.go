package dtos

type AdminClientPermissions struct {
	ClientID                 uint
	ClientIdentifier         string
	ClientCredentialsEnabled bool
	Permissions              map[uint]string
}
