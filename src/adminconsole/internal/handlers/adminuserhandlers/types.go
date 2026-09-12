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
	// UserAgent is the raw header, shown as the Device cell's tooltip so two sessions
	// whose labels read alike can still be told apart (#281).
	UserAgent string
	Clients   []string
}

type PageResult struct {
	Users    []models.User
	Total    int
	Query    string
	Page     int
	PageSize int
}
