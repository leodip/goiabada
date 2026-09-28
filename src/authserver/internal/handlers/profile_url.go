package handlers

// profileURL is the admin console page a user manages their own profile on, under the admin
// console's base URL, which each handler linking to it is handed at construction (#434).
func profileURL(adminConsoleBaseURL string) string {
	return adminConsoleBaseURL + "/account/profile"
}
