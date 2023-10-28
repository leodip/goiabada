package entities

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/internal/enums"
	"gorm.io/gorm"
)

type Client struct {
	gorm.Model
	ClientIdentifier         string `gorm:"size:32;not null;"`
	ClientSecretEncrypted    []byte
	Description              string       `gorm:"size:128;"`
	Enabled                  bool         `gorm:"not null;"`
	ConsentRequired          bool         `gorm:"not null;"`
	IsPublic                 bool         `gorm:"not null;"`
	AuthorizationCodeEnabled bool         `gorm:"not null;"`
	ClientCredentialsEnabled bool         `gorm:"not null;"`
	Permissions              []Permission `gorm:"many2many:clients_permissions;"`
	RedirectUris             []RedirectUri
}

func (c *Client) IsSystemLevelClient() bool {
	systemLevelClients := []string{
		"account-management",
		"admin-website",
	}
	for _, systemLevelClient := range systemLevelClients {
		if c.ClientIdentifier == systemLevelClient {
			return true
		}
	}
	return false
}

type Resource struct {
	gorm.Model
	ResourceIdentifier string `gorm:"size:32;not null;"`
	Description        string `gorm:"size:128;"`
}

type Permission struct {
	gorm.Model
	PermissionIdentifier string `gorm:"size:32;not null;"`
	Description          string `gorm:"size:128;"`
	ResourceID           uint   `gorm:"not null;"`
	Resource             Resource
	Clients              []Client `gorm:"many2many:clients_permissions;"`
	Users                []User   `gorm:"many2many:users_permissions;"`
}

type RedirectUri struct {
	gorm.Model
	Uri      string `gorm:"size:256;not null;"`
	ClientID uint   `gorm:"not null;"`
	Client   Client
}

type Role struct {
	gorm.Model
	RoleIdentifier string `gorm:"size:32;not null;"`
	Description    string `gorm:"size:128;not null;"`
	Users          []User `gorm:"many2many:users_roles;"`
}

type User struct {
	gorm.Model
	Enabled                              bool      `gorm:"not null;"`
	Subject                              uuid.UUID `gorm:"size:64;not null;"`
	Username                             string    `gorm:"size:32;not null;"`
	GivenName                            string    `gorm:"size:64;"`
	MiddleName                           string    `gorm:"size:64;"`
	FamilyName                           string    `gorm:"size:64;"`
	Nickname                             string    `gorm:"size:64;"`
	Website                              string    `gorm:"size:64;"`
	Gender                               string    `gorm:"size:16;"`
	Email                                string    `gorm:"size:64;"`
	EmailVerified                        bool      `gorm:"not null;"`
	EmailVerificationCodeEncrypted       []byte
	EmailVerificationCodeIssuedAt        *time.Time
	ZoneInfo                             string `gorm:"size:32;"`
	Locale                               string `gorm:"size:8;"`
	BirthDate                            *time.Time
	PhoneNumber                          string `gorm:"size:32;"`
	PhoneNumberVerified                  bool   `gorm:"not null;"`
	PhoneNumberVerificationCodeEncrypted []byte
	PhoneNumberVerificationCodeIssuedAt  *time.Time
	PhoneNumberVerificationHit           int    `gorm:"not null;"`
	AddressLine1                         string `gorm:"size:64;"`
	AddressLine2                         string `gorm:"size:64;"`
	AddressLocality                      string `gorm:"size:64;"`
	AddressRegion                        string `gorm:"size:64;"`
	AddressPostalCode                    string `gorm:"size:32;"`
	AddressCountry                       string `gorm:"size:64;"`
	PasswordHash                         string `gorm:"size:64;not null;"`
	OTPSecret                            string `gorm:"size:64;"`
	OTPEnabled                           bool   `gorm:"not null;"`
	ForgotPasswordCodeEncrypted          []byte
	ForgotPasswordCodeIssuedAt           *time.Time
	Roles                                []Role       `gorm:"many2many:users_roles;"`
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

func (u *User) GetRoleIdentifiers() []string {
	roleIdentifiers := []string{}

	for _, user := range u.Roles {
		roleIdentifiers = append(roleIdentifiers, user.RoleIdentifier)
	}

	return roleIdentifiers
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
	gorm.Model
	UserID   uint `gorm:"not null;"`
	User     User
	ClientID uint `gorm:"not null;"`
	Client   Client
	Scope    string `gorm:"size:512;not null;"`
}

type UserSession struct {
	gorm.Model
	SessionIdentifier  string    `gorm:"size:64;not null;"`
	Started            time.Time `gorm:"not null;"`
	LastAccessed       time.Time `gorm:"not null;"`
	AuthMethods        string    `gorm:"size:64;not null;"`
	RequestedAcrValues string    `gorm:"size:64;not null;"`
	AuthTime           time.Time `gorm:"not null;"`
	IpAddress          string    `gorm:"size:512;not null;"`
	DeviceName         string    `gorm:"size:256;not null;"`
	DeviceType         string    `gorm:"size:32;not null;"`
	DeviceOS           string    `gorm:"size:64;not null;"`
	UserID             uint      `gorm:"not null;"`
	User               User
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

type Code struct {
	gorm.Model
	Code                string `gorm:"size:160;not null;"`
	ClientID            uint   `gorm:"not null;"`
	Client              Client
	CodeChallenge       string `gorm:"size:256;not null;"`
	CodeChallengeMethod string `gorm:"size:10;not null;"`
	Scope               string `gorm:"size:512;not null;"`
	State               string `gorm:"size:128;not null;"`
	Nonce               string `gorm:"size:128;not null;"`
	RedirectUri         string `gorm:"size:256;not null;"`
	UserID              uint   `gorm:"not null;"`
	User                User
	IpAddress           string    `gorm:"size:64;not null;"`
	UserAgent           string    `gorm:"size:512;not null;"`
	ResponseMode        string    `gorm:"size:16;not null;"`
	AuthenticatedAt     time.Time `gorm:"not null;"`
	SessionIdentifier   string    `gorm:"size:64;not null;"`
	AcrLevel            string    `gorm:"size:16;not null;"`
	AuthMethods         string    `gorm:"size:64;not null;"`
	Used                bool      `gorm:"not null;"`
}

type KeyPair struct {
	gorm.Model
	KeyIdentifier string `gorm:"size:64;not null;"`
	Type          string `gorm:"size:16;not null;"`
	Algorithm     string `gorm:"size:16;not null;"`
	PrivateKeyPEM string `gorm:"size:6000;not null;"`
	PublicKeyPEM  string `gorm:"size:6000;not null;"`
}

type Settings struct {
	gorm.Model
	AppName                                   string `gorm:"size:32;not null;"`
	Issuer                                    string `gorm:"size:64;not null;"`
	AuthorizationCodeExpirationInSeconds      int    `gorm:"not null;"`
	TokenExpirationInSeconds                  int    `gorm:"not null;"`
	RefreshTokenExpirationInSeconds           int    `gorm:"not null;"`
	UserSessionIdleTimeoutInSeconds           int    `gorm:"not null;"`
	UserSessionMaxLifetimeInSeconds           int    `gorm:"not null;"`
	AcrLevel1MaxAgeInSeconds                  int    `gorm:"not null;"`
	AcrLevel2MaxAgeInSeconds                  int    `gorm:"not null;"`
	AcrLevel3MaxAgeInSeconds                  int    `gorm:"not null;"`
	SessionAuthenticationKey                  []byte `gorm:"not null;"`
	SessionEncryptionKey                      []byte `gorm:"not null;"`
	AESEncryptionKey                          []byte `gorm:"not null;"`
	IncludeRolesInIdToken                     bool   `gorm:"not null;"`
	SMTPHost                                  string `gorm:"size:64;"`
	SMTPPort                                  int
	SMTPUsername                              string `gorm:"size:64;"`
	SMTPPasswordEncrypted                     []byte
	SMTPFromName                              string `gorm:"size:64;"`
	SMTPFromEmail                             string `gorm:"size:64;"`
	SMSProvider                               string `gorm:"size:32;"`
	SMSConfigEncrypted                        []byte
	PasswordPolicy                            enums.PasswordPolicy
	SelfRegistrationEnabled                   bool `gorm:"not null;"`
	SelfRegistrationRequiresEmailVerification bool `gorm:"not null;"`
}

func (s *Settings) IsSMSEnabled() bool {
	return len(s.SMSProvider) > 0 && len(s.SMSConfigEncrypted) > 0
}

type PreRegistration struct {
	gorm.Model
	Email                     string `gorm:"size:64;"`
	PasswordHash              string `gorm:"size:64;not null;"`
	VerificationCodeEncrypted []byte
	VerificationCodeIssuedAt  *time.Time
}

type Group struct {
	gorm.Model
	GroupIdentifier string `gorm:"size:32;not null;"`
	Description     string `gorm:"size:128;"`
	Users           []User `gorm:"many2many:users_groups;"`
	Attributes      []GroupAttribute
	Permissions     []Permission `gorm:"many2many:groups_permissions;"`
}

type UserAttribute struct {
	gorm.Model
	Key            string `gorm:"size:32;not null;"`
	Value          string `gorm:"size:256;not null;"`
	IncludeInToken bool   `gorm:"not null;"`
	UserID         uint   `gorm:"not null;"`
	User           User
}

type GroupAttribute struct {
	gorm.Model
	Key            string `gorm:"size:32;not null;"`
	Value          string `gorm:"size:256;not null;"`
	IncludeInToken bool   `gorm:"not null;"`
	GroupID        uint   `gorm:"not null;"`
	Group          Group
}
