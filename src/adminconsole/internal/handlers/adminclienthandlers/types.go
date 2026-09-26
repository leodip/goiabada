package adminclienthandlers

import "time"

type PermissionsPostInput struct {
	ClientId               int64   `json:"clientId"`
	AssignedPermissionsIds []int64 `json:"assignedPermissionsIds"`
}

type RedirectURIsPostInput struct {
	ClientId     int64    `json:"clientId"`
	RedirectURIs []string `json:"redirectURIs"`
	// ExpectedRedirectURIs is the list as the page loaded it, passed through unchanged so the auth
	// server can refuse a save from an outdated page (#428).
	ExpectedRedirectURIs []string `json:"expectedRedirectURIs"`
	Ids                  []int64  `json:"ids"`
}

type WebOriginsPostInput struct {
	ClientId   int64    `json:"clientId"`
	WebOrigins []string `json:"webOrigins"`
	Ids        []int64  `json:"ids"`
}

type SessionInfo struct {
	UserSessionId int64
	UserId        int64
	UserEmail     string
	UserFullName  string
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
	Page     int
	PageSize int
	Total    int
	Sessions []SessionInfo
}
