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
	Clients                   []string
}
