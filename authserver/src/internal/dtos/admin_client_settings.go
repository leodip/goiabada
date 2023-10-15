package dtos

type AdminClientSettings struct {
	ClientID         uint
	ClientIdentifier string
	Description      string
	Enabled          bool
	ConsentRequired  bool
}
