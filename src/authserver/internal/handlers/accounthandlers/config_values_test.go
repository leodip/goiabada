package accounthandlers

// The configuration values this package's tests hand to the handlers they build, as routes.go
// hands the process's. Both differ from every configuration default, and nothing in this
// package loads the configuration, so a link built from them fails for a handler that reads
// its base URL from anywhere but its own parameter (#434).
const (
	testBaseURL             = "https://auth.test"
	testAdminConsoleBaseURL = "https://admin.test"
)
