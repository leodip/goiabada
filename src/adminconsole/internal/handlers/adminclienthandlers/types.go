package adminclienthandlers

type PermissionsPostInput struct {
	ClientId               int64   `json:"clientId"`
	AssignedPermissionsIds []int64 `json:"assignedPermissionsIds"`
}

type RedirectURIsPostInput struct {
	ClientId     int64    `json:"clientId"`
	RedirectURIs []string `json:"redirectURIs"`
	Ids          []int64  `json:"ids"`
}

type SessionInfo struct {
	UserSessionId             int64
	UserId                    int64
	UserEmail                 string
	UserFullName              string
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
	Page     int
	PageSize int
	Total    int
	Sessions []SessionInfo
}
