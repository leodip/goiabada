package admingrouphandlers

import "github.com/leodip/goiabada/core/models"

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

type PageResult struct {
	Page     int
	PageSize int
	Total    int
	Users    []models.User
}
