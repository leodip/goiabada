package adminuserhandlers

import (
	"time"

	"github.com/leodip/goiabada/core/api"
)

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
	UserSessionId int64
	IsCurrent     bool
	// Started and LastAccessed are the instants themselves rather than pre-rendered text: the
	// page formats them with the DateTime and Since template functions, which read the layout
	// and the relative phrase from the viewer's catalog. Formatting them here produced an
	// English RFC1123 date beside a Go duration string under every locale, because Go's
	// time.Format has no locale and Duration.String() is not anybody's language (#373).
	Started      *time.Time
	LastAccessed *time.Time
	IpAddress    string
	DeviceName   string
	DeviceType   string
	DeviceOS     string
	// UserAgent is the raw header, shown as the Device cell's tooltip so two sessions
	// whose labels read alike can still be told apart (#281).
	UserAgent string
	Clients   []string
}

type PageResult struct {
	Users    []api.UserResponse
	Total    int
	Query    string
	Page     int
	PageSize int
}
