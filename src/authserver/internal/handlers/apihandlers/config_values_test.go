package apihandlers

// The configuration values this package's tests hand to the handlers they build, as routes.go
// hands the process's. The base URLs differ from every configuration default, and nothing in
// this package loads the configuration, so a URL built from them fails for a handler that reads
// its base URL from anywhere but its own parameter. testMaxUploadBytes is the configured
// default, so the upload cases that are not about the cap see the cap a deployment does (#434).
const (
	testBaseURL             = "https://auth.test"
	testAdminConsoleBaseURL = "https://admin.test"
	testMaxUploadBytes      = int64(3 * 1024 * 1024)
)
