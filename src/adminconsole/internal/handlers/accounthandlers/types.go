package accounthandlers

type EmailSendVerificationResult struct {
	EmailVerified         bool
	EmailVerificationSent bool
	EmailDestination      string
	TooManyRequests       bool
	WaitInSeconds         int
}
