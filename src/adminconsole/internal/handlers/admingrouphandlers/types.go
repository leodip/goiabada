package admingrouphandlers

type UserResult struct {
	Id           int64
	Subject      string
	Username     string
	Email        string
	GivenName    string
	MiddleName   string
	FamilyName   string
	AddedToGroup bool
}

type SearchResult struct {
	Users []UserResult
}
