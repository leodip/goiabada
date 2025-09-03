package api

type UpdateUserEnabledRequest struct {
	Enabled bool `json:"enabled"`
}

type CreateUserAdminRequest struct {
	Email           string `json:"email"`
	EmailVerified   bool   `json:"emailVerified"`
	GivenName       string `json:"givenName"`
	MiddleName      string `json:"middleName"`
	FamilyName      string `json:"familyName"`
	SetPasswordType string `json:"setPasswordType"`    // "now" or "email"
	Password        string `json:"password,omitempty"` // if "now"
}

type UpdateUserProfileRequest struct {
	Username            string `json:"username"`
	GivenName           string `json:"givenName"`
	MiddleName          string `json:"middleName"`
	FamilyName          string `json:"familyName"`
	Nickname            string `json:"nickname"`
	Website             string `json:"website"`
	Gender              string `json:"gender"`
	DateOfBirth         string `json:"dateOfBirth"`
	ZoneInfoCountryName string `json:"zoneInfoCountryName"`
	ZoneInfo            string `json:"zoneInfo"`
	Locale              string `json:"locale"`
}

type UpdateUserAddressRequest struct {
	AddressLine1      string `json:"addressLine1"`
	AddressLine2      string `json:"addressLine2"`
	AddressLocality   string `json:"addressLocality"`
	AddressRegion     string `json:"addressRegion"`
	AddressPostalCode string `json:"addressPostalCode"`
	AddressCountry    string `json:"addressCountry"`
}

type CreateUserAttributeRequest struct {
	Key                  string `json:"key"`
	Value                string `json:"value"`
	IncludeInIdToken     bool   `json:"includeInIdToken"`
	IncludeInAccessToken bool   `json:"includeInAccessToken"`
	UserId               int64  `json:"userId"`
}

type UpdateUserAttributeRequest struct {
	Key                  string `json:"key"`
	Value                string `json:"value"`
	IncludeInIdToken     bool   `json:"includeInIdToken"`
	IncludeInAccessToken bool   `json:"includeInAccessToken"`
}