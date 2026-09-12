package accounthandlers

type EmailSendVerificationResult struct {
	EmailVerified         bool
	EmailVerificationSent bool
	EmailDestination      string
	TooManyRequests       bool
	WaitInSeconds         int
}

type ConsentInfo struct {
	ConsentId         int64
	Client            string
	ClientDescription string
	GrantedAt         string
	Scope             string
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
