package adminuserhandlers

import "github.com/leodip/goiabada/core/models"

type Address struct {
	AddressLine1      string
	AddressLine2      string
	AddressLocality   string
	AddressRegion     string
	AddressPostalCode string
	AddressCountry    string
}

type ConsentInfo struct {
	ConsentId         int64
	Client            string
	ClientDescription string
	GrantedAt         string
	Scope             string
}

type GroupsPostInput struct {
	AssignedGroupsIds []int64 `json:"assignedGroupsIds"`
}

type PermissionsPostInput struct {
	AssignedPermissionsIds []int64 `json:"assignedPermissionsIds"`
}

type SessionInfo struct {
	UserSessionId             int64
	IsCurrent                 bool
	StartedAt                 string
	DurationSinceStarted      string
	LastAcessedAt             string
	DurationSinceLastAccessed string
	IpAddress                 string
	DeviceName                string
	DeviceType                string
	DeviceOS                  string
	Clients                   []string
}

type PageResult struct {
	Users    []models.User
	Total    int
	Query    string
	Page     int
	PageSize int
}
