package entitiesv2

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/enums"
)

type Client struct {
	Id                                      int64
	CreatedAt                               time.Time
	UpdatedAt                               time.Time
	ClientIdentifier                        string
	ClientSecretEncrypted                   []byte
	Description                             string
	Enabled                                 bool
	ConsentRequired                         bool
	IsPublic                                bool
	AuthorizationCodeEnabled                bool
	ClientCredentialsEnabled                bool
	TokenExpirationInSeconds                int
	RefreshTokenOfflineIdleTimeoutInSeconds int
	RefreshTokenOfflineMaxLifetimeInSeconds int
	IncludeOpenIDConnectClaimsInAccessToken string
	DefaultAcrLevel                         enums.AcrLevel
	Permissions                             []Permission
	RedirectURIs                            []RedirectURI
	WebOrigins                              []WebOrigin
}

func (c *Client) IsSystemLevelClient() bool {
	systemLevelClients := []string{
		constants.SystemClientIdentifier,
	}
	for _, systemLevelClient := range systemLevelClients {
		if c.ClientIdentifier == systemLevelClient {
			return true
		}
	}
	return false
}

type WebOrigin struct {
	Id        int64 `gorm:"primarykey"`
	CreatedAt time.Time
	Origin    string `gorm:"size:256;not null;"`
	ClientId  int64  `gorm:"not null;"`
	Client    Client
}

type Resource struct {
	Id                 int64 `gorm:"primarykey"`
	CreatedAt          time.Time
	UpdatedAt          time.Time
	ResourceIdentifier string `gorm:"size:32;not null;index:idx_resource_identifier,unique"`
	Description        string `gorm:"size:128;"`
}

func (r *Resource) IsSystemLevelResource() bool {
	systemLevelResources := []string{
		constants.AuthServerResourceIdentifier,
	}
	for _, systemLevelResource := range systemLevelResources {
		if r.ResourceIdentifier == systemLevelResource {
			return true
		}
	}
	return false
}

type Permission struct {
	Id                   int64 `gorm:"primarykey"`
	CreatedAt            time.Time
	UpdatedAt            time.Time
	PermissionIdentifier string `gorm:"size:32;not null;index:idx_permission_identifier,unique"`
	Description          string `gorm:"size:128;"`
	ResourceId           int64  `gorm:"not null;"`
	Resource             Resource
	Clients              []Client `gorm:"many2many:clients_permissions;"`
	Users                []User   `gorm:"many2many:users_permissions;"`
}

type RedirectURI struct {
	Id        int64
	CreatedAt time.Time
	URI       string
	ClientId  int64
	Client    Client
}

type User struct {
	Id                                   int64 `gorm:"primarykey"`
	CreatedAt                            time.Time
	UpdatedAt                            time.Time
	Enabled                              bool      `gorm:"not null;"`
	Subject                              uuid.UUID `gorm:"size:64;not null;index:idx_subject,unique"`
	Username                             string    `gorm:"size:32;not null;index:idx_username"`
	GivenName                            string    `gorm:"size:64;index:idx_given_name"`
	MiddleName                           string    `gorm:"size:64;index:idx_middle_name"`
	FamilyName                           string    `gorm:"size:64;index:idx_family_name"`
	Nickname                             string    `gorm:"size:64;"`
	Website                              string    `gorm:"size:128;"`
	Gender                               string    `gorm:"size:16;"`
	Email                                string    `gorm:"size:64;index:idx_email,unique"`
	EmailVerified                        bool      `gorm:"not null;"`
	EmailVerificationCodeEncrypted       []byte
	EmailVerificationCodeIssuedAt        *time.Time
	ZoneInfoCountryName                  string `gorm:"size:128;"`
	ZoneInfo                             string `gorm:"size:128;"`
	Locale                               string `gorm:"size:32;"`
	BirthDate                            *time.Time
	PhoneNumber                          string `gorm:"size:32;"`
	PhoneNumberVerified                  bool   `gorm:"not null;"`
	PhoneNumberVerificationCodeEncrypted []byte
	PhoneNumberVerificationCodeIssuedAt  *time.Time
	AddressLine1                         string `gorm:"size:64;"`
	AddressLine2                         string `gorm:"size:64;"`
	AddressLocality                      string `gorm:"size:64;"`
	AddressRegion                        string `gorm:"size:64;"`
	AddressPostalCode                    string `gorm:"size:32;"`
	AddressCountry                       string `gorm:"size:32;"`
	PasswordHash                         string `gorm:"size:64;not null;"`
	OTPSecret                            string `gorm:"size:64;"`
	OTPEnabled                           bool   `gorm:"not null;"`
	ForgotPasswordCodeEncrypted          []byte
	ForgotPasswordCodeIssuedAt           *time.Time
	Groups                               []Group      `gorm:"many2many:users_groups;"`
	Permissions                          []Permission `gorm:"many2many:users_permissions;"`
	Attributes                           []UserAttribute
}

func (u *User) HasAddress() bool {
	if len(strings.TrimSpace(u.AddressLine1)) > 0 ||
		len(strings.TrimSpace(u.AddressLine2)) > 0 ||
		len(strings.TrimSpace(u.AddressLocality)) > 0 ||
		len(strings.TrimSpace(u.AddressRegion)) > 0 ||
		len(strings.TrimSpace(u.AddressPostalCode)) > 0 ||
		len(strings.TrimSpace(u.AddressCountry)) > 0 {
		return true
	}
	return false
}

func (u *User) GetAddressClaim() map[string]string {
	addressClaim := make(map[string]string)

	formatted := ""
	streetAddress := fmt.Sprintf("%v\r\n%v", u.AddressLine1, u.AddressLine2)
	if len(strings.TrimSpace(streetAddress)) > 0 {
		addressClaim["street_address"] = streetAddress
		formatted += streetAddress + "\r\n"
	}

	if len(strings.TrimSpace(u.AddressLocality)) > 0 {
		addressClaim["locality"] = u.AddressLocality
		formatted += u.AddressLocality + "\r\n"
	}

	if len(strings.TrimSpace(u.AddressRegion)) > 0 {
		addressClaim["region"] = u.AddressRegion
		formatted += u.AddressRegion + "\r\n"
	}

	if len(strings.TrimSpace(u.AddressPostalCode)) > 0 {
		addressClaim["postal_code"] = u.AddressPostalCode
		formatted += u.AddressPostalCode + "\r\n"
	}

	if len(strings.TrimSpace(u.AddressCountry)) > 0 {
		addressClaim["country"] = u.AddressCountry
		formatted += u.AddressCountry + "\r\n"
	}

	if len(strings.TrimSpace(u.AddressCountry)) > 0 {
		addressClaim["formatted"] = strings.TrimSpace(formatted)
	}

	return addressClaim
}

func (u *User) GetDateOfBirthFormatted() string {
	dateOfBirthFormatted := ""
	if u != nil && u.BirthDate != nil {
		dateOfBirthFormatted = u.BirthDate.Format("2006-01-02")
	}
	return dateOfBirthFormatted
}

func (u *User) GetFullName() string {
	fullName := ""

	if u != nil {
		if len(u.GivenName) > 0 {
			fullName += u.GivenName
		}

		if len(u.MiddleName) > 0 {
			fullName += " " + u.MiddleName
		}

		if len(u.FamilyName) > 0 {
			fullName += " " + u.FamilyName
		}
		fullName = strings.TrimSpace(fullName)
	}

	return fullName
}

type UserConsent struct {
	Id        int64 `gorm:"primarykey"`
	CreatedAt time.Time
	UpdatedAt time.Time
	UserId    int64 `gorm:"not null;"`
	User      User
	ClientId  int64 `gorm:"not null;"`
	Client    Client
	Scope     string `gorm:"size:512;not null;"`
	GrantedAt time.Time
}

func (uc *UserConsent) HasScope(scope string) bool {
	if len(uc.Scope) == 0 {
		return false
	}
	return slices.Contains(strings.Split(uc.Scope, " "), scope)
}

type UserSession struct {
	Id                int64     `gorm:"primarykey"`
	SessionIdentifier string    `gorm:"size:64;not null;index:idx_session_identifier,unique"`
	Started           time.Time `gorm:"not null;"`
	LastAccessed      time.Time `gorm:"not null;"`
	AuthMethods       string    `gorm:"size:64;not null;"`
	AcrLevel          string    `gorm:"size:128;not null;"`
	AuthTime          time.Time `gorm:"not null;"`
	IpAddress         string    `gorm:"size:512;not null;"`
	DeviceName        string    `gorm:"size:256;not null;"`
	DeviceType        string    `gorm:"size:32;not null;"`
	DeviceOS          string    `gorm:"size:64;not null;"`
	UserId            int64     `gorm:"not null;"`
	User              User
	Clients           []UserSessionClient
}

func (us *UserSession) isValidSinceStarted(userSessionMaxLifetimeInSeconds int) bool {
	utcNow := time.Now().UTC()
	max := us.Started.Add(time.Second * time.Duration(userSessionMaxLifetimeInSeconds))
	return utcNow.Before(max) || utcNow.Equal(max)
}

func (us *UserSession) isValidSinceLastAcessed(userSessionIdleTimeoutInSeconds int) bool {
	utcNow := time.Now().UTC()
	max := us.LastAccessed.Add(time.Second * time.Duration(userSessionIdleTimeoutInSeconds))
	return utcNow.Before(max) || utcNow.Equal(max)
}

func (us *UserSession) IsValid(userSessionIdleTimeoutInSeconds int, userSessionMaxLifetimeInSeconds int,
	requestedMaxAgeInSeconds *int) bool {

	isValid := us.isValidSinceLastAcessed(userSessionIdleTimeoutInSeconds) &&
		us.isValidSinceStarted(userSessionMaxLifetimeInSeconds)

	if requestedMaxAgeInSeconds != nil {
		isValid = isValid && us.isValidSinceStarted(*requestedMaxAgeInSeconds)
	}

	return isValid
}

type UserSessionClient struct {
	Id            int64       `gorm:"primarykey"`
	UserSessionId int64       `gorm:"not null;"`
	UserSession   UserSession `gorm:"constraint:OnDelete:CASCADE;"`
	ClientId      int64       `gorm:"not null;"`
	Client        Client
	Started       time.Time `gorm:"not null;"`
	LastAccessed  time.Time `gorm:"not null;"`
}

type Code struct {
	Id                  int64 `gorm:"primarykey"`
	CreatedAt           time.Time
	UpdatedAt           time.Time
	Code                string `gorm:"-"`
	CodeHash            string `gorm:"size:64;not null;index:idx_code_hash,unique"`
	ClientId            int64  `gorm:"not null;"`
	Client              Client
	CodeChallenge       string `gorm:"size:256;not null;"`
	CodeChallengeMethod string `gorm:"size:10;not null;"`
	Scope               string `gorm:"size:512;not null;"`
	State               string `gorm:"size:512;not null;"`
	Nonce               string `gorm:"size:512;not null;"`
	RedirectURI         string `gorm:"size:256;not null;"`
	UserId              int64  `gorm:"not null;"`
	User                User
	IpAddress           string    `gorm:"size:64;not null;"`
	UserAgent           string    `gorm:"size:512;not null;"`
	ResponseMode        string    `gorm:"size:16;not null;"`
	AuthenticatedAt     time.Time `gorm:"not null;"`
	SessionIdentifier   string    `gorm:"size:64;not null;"`
	AcrLevel            string    `gorm:"size:128;not null;"`
	AuthMethods         string    `gorm:"size:64;not null;"`
	Used                bool      `gorm:"not null;"`
}

type RefreshToken struct {
	Id                      int64 `gorm:"primarykey"`
	CreatedAt               time.Time
	UpdatedAt               time.Time
	CodeId                  int64 `gorm:"not null;"`
	Code                    Code
	RefreshTokenJti         string `gorm:"size:64;not null;index:idx_refresh_token_jti,unique"`
	PreviousRefreshTokenJti string `gorm:"size:64;not null;"`
	FirstRefreshTokenJti    string `gorm:"size:64;not null;"`
	SessionIdentifier       string `gorm:"size:64;not null;"`
	RefreshTokenType        string `gorm:"size:16;not null;"`
	Scope                   string `gorm:"size:512;not null;"`
	IssuedAt                time.Time
	ExpiresAt               time.Time
	MaxLifetime             *time.Time
	Revoked                 bool `gorm:"not null;"`
}

type KeyPair struct {
	Id                int64 `gorm:"primarykey"`
	CreatedAt         time.Time
	UpdatedAt         time.Time
	State             string `gorm:"not null;index:idx_state"`
	KeyIdentifier     string `gorm:"size:64;not null;"`
	Type              string `gorm:"size:16;not null;"`
	Algorithm         string `gorm:"size:16;not null;"`
	PrivateKeyPEM     []byte
	PublicKeyPEM      []byte
	PublicKeyASN1_DER []byte
	PublicKeyJWK      []byte
}

type Settings struct {
	Id                                        int64 `gorm:"primarykey"`
	CreatedAt                                 time.Time
	UpdatedAt                                 time.Time
	AppName                                   string `gorm:"size:32;not null;"`
	Issuer                                    string `gorm:"size:64;not null;"`
	UITheme                                   string `gorm:"size:32;not null;"`
	PasswordPolicy                            enums.PasswordPolicy
	SelfRegistrationEnabled                   bool   `gorm:"not null;"`
	SelfRegistrationRequiresEmailVerification bool   `gorm:"not null;"`
	TokenExpirationInSeconds                  int    `gorm:"not null;"`
	RefreshTokenOfflineIdleTimeoutInSeconds   int    `gorm:"not null;"`
	RefreshTokenOfflineMaxLifetimeInSeconds   int    `gorm:"not null;"`
	UserSessionIdleTimeoutInSeconds           int    `gorm:"not null;"`
	UserSessionMaxLifetimeInSeconds           int    `gorm:"not null;"`
	IncludeOpenIDConnectClaimsInAccessToken   bool   `gorm:"not null;"`
	SessionAuthenticationKey                  []byte `gorm:"not null;"`
	SessionEncryptionKey                      []byte `gorm:"not null;"`
	AESEncryptionKey                          []byte `gorm:"not null;"`
	SMTPHost                                  string `gorm:"size:128;"`
	SMTPPort                                  int
	SMTPUsername                              string `gorm:"size:64;"`
	SMTPPasswordEncrypted                     []byte
	SMTPFromName                              string `gorm:"size:64;"`
	SMTPFromEmail                             string `gorm:"size:64;"`
	SMTPEncryption                            string `gorm:"size:16;"`
	SMTPEnabled                               bool   `gorm:"not null;"`
	SMSProvider                               string `gorm:"size:32;"`
	SMSConfigEncrypted                        []byte
}

type PreRegistration struct {
	Id                        int64 `gorm:"primarykey"`
	CreatedAt                 time.Time
	UpdatedAt                 time.Time
	Email                     string `gorm:"size:64;index:idx_pre_reg_email"`
	PasswordHash              string `gorm:"size:64;not null;"`
	VerificationCodeEncrypted []byte
	VerificationCodeIssuedAt  *time.Time
}

type Group struct {
	Id                   int64 `gorm:"primarykey"`
	CreatedAt            time.Time
	UpdatedAt            time.Time
	GroupIdentifier      string `gorm:"size:32;not null;index:idx_group_identifier,unique"`
	Description          string `gorm:"size:128;"`
	Users                []User `gorm:"many2many:users_groups;"`
	Attributes           []GroupAttribute
	Permissions          []Permission `gorm:"many2many:groups_permissions;"`
	IncludeInIdToken     bool         `gorm:"not null;"`
	IncludeInAccessToken bool         `gorm:"not null;"`
}

type UserAttribute struct {
	Id                   int64 `gorm:"primarykey"`
	CreatedAt            time.Time
	UpdatedAt            time.Time
	Key                  string `gorm:"size:32;not null;"`
	Value                string `gorm:"size:256;not null;"`
	IncludeInIdToken     bool   `gorm:"not null;"`
	IncludeInAccessToken bool   `gorm:"not null;"`
	UserId               int64  `gorm:"not null;"`
	User                 User
}

type GroupAttribute struct {
	Id                   int64 `gorm:"primarykey"`
	CreatedAt            time.Time
	UpdatedAt            time.Time
	Key                  string `gorm:"size:32;not null;"`
	Value                string `gorm:"size:256;not null;"`
	IncludeInIdToken     bool   `gorm:"not null;"`
	IncludeInAccessToken bool   `gorm:"not null;"`
	GroupId              int64  `gorm:"not null;"`
	Group                Group
}

type HttpSession struct {
	Id        int64  `gorm:"primaryKey;autoIncrement"`
	Data      string `gorm:"type:LONGTEXT"`
	CreatedAt time.Time
	UpdatedAt time.Time
	ExpiresOn time.Time `gorm:"index:idx_httpsess_expires"`
}
