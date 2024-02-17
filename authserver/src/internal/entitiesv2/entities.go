package entitiesv2

import (
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/enums"
)

type Client struct {
	Id                                      int64          `db:"id" fieldtag:"pk"`
	CreatedAt                               sql.NullTime   `db:"created_at"`
	UpdatedAt                               sql.NullTime   `db:"updated_at"`
	ClientIdentifier                        string         `db:"client_identifier"`
	ClientSecretEncrypted                   []byte         `db:"client_secret_encrypted"`
	Description                             string         `db:"description"`
	Enabled                                 bool           `db:"enabled"`
	ConsentRequired                         bool           `db:"consent_required"`
	IsPublic                                bool           `db:"is_public"`
	AuthorizationCodeEnabled                bool           `db:"authorization_code_enabled"`
	ClientCredentialsEnabled                bool           `db:"client_credentials_enabled"`
	TokenExpirationInSeconds                int            `db:"token_expiration_in_seconds"`
	RefreshTokenOfflineIdleTimeoutInSeconds int            `db:"refresh_token_offline_idle_timeout_in_seconds"`
	RefreshTokenOfflineMaxLifetimeInSeconds int            `db:"refresh_token_offline_max_lifetime_in_seconds"`
	IncludeOpenIDConnectClaimsInAccessToken string         `db:"include_open_id_connect_claims_in_access_token"`
	DefaultAcrLevel                         enums.AcrLevel `db:"default_acr_level"`
	Permissions                             []Permission   `db:"-"`
	RedirectURIs                            []RedirectURI  `db:"-"`
	WebOrigins                              []WebOrigin    `db:"-"`
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
	Id        int64        `db:"id" fieldtag:"pk"`
	CreatedAt sql.NullTime `db:"created_at"`
	Origin    string       `db:"origin"`
	ClientId  int64        `db:"client_id"`
	Client    Client       `db:"-"`
}

type Resource struct {
	Id                 int64        `db:"id" fieldtag:"pk"`
	CreatedAt          sql.NullTime `db:"created_at"`
	UpdatedAt          sql.NullTime `db:"updated_at"`
	ResourceIdentifier string       `db:"resource_identifier"`
	Description        string       `db:"description"`
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
	Id                   int64        `db:"id" fieldtag:"pk"`
	CreatedAt            sql.NullTime `db:"created_at"`
	UpdatedAt            sql.NullTime `db:"updated_at"`
	PermissionIdentifier string       `db:"permission_identifier"`
	Description          string       `db:"description"`
	ResourceId           int64        `db:"resource_id"`
	Resource             Resource     `db:"-"`
	Clients              []Client     `db:"-"`
	Users                []User       `db:"-"`
}

type RedirectURI struct {
	Id        int64        `db:"id" fieldtag:"pk"`
	CreatedAt sql.NullTime `db:"created_at"`
	URI       string       `db:"uri"`
	ClientId  int64        `db:"client_id"`
	Client    Client       `db:"-"`
}

type User struct {
	Id                                   int64           `db:"id" fieldtag:"pk"`
	CreatedAt                            sql.NullTime    `db:"created_at"`
	UpdatedAt                            sql.NullTime    `db:"updated_at"`
	Enabled                              bool            `db:"enabled"`
	Subject                              uuid.UUID       `db:"subject"`
	Username                             string          `db:"username"`
	GivenName                            string          `db:"given_name"`
	MiddleName                           string          `db:"middle_name"`
	FamilyName                           string          `db:"family_name"`
	Nickname                             string          `db:"nickname"`
	Website                              string          `db:"website"`
	Gender                               string          `db:"gender"`
	Email                                string          `db:"email"`
	EmailVerified                        bool            `db:"email_verified"`
	EmailVerificationCodeEncrypted       []byte          `db:"email_verification_code_encrypted"`
	EmailVerificationCodeIssuedAt        sql.NullTime    `db:"email_verification_code_issued_at"`
	ZoneInfoCountryName                  string          `db:"zone_info_country_name"`
	ZoneInfo                             string          `db:"zone_info"`
	Locale                               string          `db:"locale"`
	BirthDate                            sql.NullTime    `db:"birth_date"`
	PhoneNumber                          string          `db:"phone_number"`
	PhoneNumberVerified                  bool            `db:"phone_number_verified"`
	PhoneNumberVerificationCodeEncrypted []byte          `db:"phone_number_verification_code_encrypted"`
	PhoneNumberVerificationCodeIssuedAt  sql.NullTime    `db:"phone_number_verification_code_issued_at"`
	AddressLine1                         string          `db:"address_line1"`
	AddressLine2                         string          `db:"address_line2"`
	AddressLocality                      string          `db:"address_locality"`
	AddressRegion                        string          `db:"address_region"`
	AddressPostalCode                    string          `db:"address_postal_code"`
	AddressCountry                       string          `db:"address_country"`
	PasswordHash                         string          `db:"password_hash"`
	OTPSecret                            string          `db:"otp_secret"`
	OTPEnabled                           bool            `db:"otp_enabled"`
	ForgotPasswordCodeEncrypted          []byte          `db:"forgot_password_code_encrypted"`
	ForgotPasswordCodeIssuedAt           sql.NullTime    `db:"forgot_password_code_issued_at"`
	Groups                               []Group         `db:"-"`
	Permissions                          []Permission    `db:"-"`
	Attributes                           []UserAttribute `db:"-"`
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
	if u != nil && u.BirthDate.Valid {
		dateOfBirthFormatted = u.BirthDate.Time.Format("2006-01-02")
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
	Id        int64        `db:"id" fieldtag:"pk"`
	CreatedAt sql.NullTime `db:"created_at"`
	UpdatedAt sql.NullTime `db:"updated_at"`
	UserId    int64        `db:"user_id"`
	User      User         `db:"-"`
	ClientId  int64        `db:"client_id"`
	Client    Client       `db:"-"`
	Scope     string       `db:"scope"`
	GrantedAt sql.NullTime `db:"granted_at"`
}

func (uc *UserConsent) HasScope(scope string) bool {
	if len(uc.Scope) == 0 {
		return false
	}
	return slices.Contains(strings.Split(uc.Scope, " "), scope)
}

type UserSession struct {
	Id                int64               `db:"id" fieldtag:"pk"`
	CreatedAt         sql.NullTime        `db:"created_at"`
	UpdatedAt         sql.NullTime        `db:"updated_at"`
	SessionIdentifier string              `db:"session_identifier"`
	Started           time.Time           `db:"started"`
	LastAccessed      time.Time           `db:"last_accessed"`
	AuthMethods       string              `db:"auth_methods"`
	AcrLevel          string              `db:"acr_level"`
	AuthTime          time.Time           `db:"auth_time"`
	IpAddress         string              `db:"ip_address"`
	DeviceName        string              `db:"device_name"`
	DeviceType        string              `db:"device_type"`
	DeviceOS          string              `db:"device_os"`
	UserId            int64               `db:"user_id"`
	User              User                `db:"-"`
	Clients           []UserSessionClient `db:"-"`
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
	Id            int64        `db:"id" fieldtag:"pk"`
	CreatedAt     sql.NullTime `db:"created_at"`
	UpdatedAt     sql.NullTime `db:"updated_at"`
	UserSessionId int64        `db:"user_session_id"`
	UserSession   UserSession  `db:"-"`
	ClientId      int64        `db:"client_id"`
	Client        Client       `db:"-"`
	Started       time.Time    `db:"started"`
	LastAccessed  time.Time    `db:"last_accessed"`
}

type Code struct {
	Id                  int64        `db:"id" fieldtag:"pk"`
	CreatedAt           sql.NullTime `db:"created_at"`
	UpdatedAt           sql.NullTime `db:"updated_at"`
	Code                string       `db:"-"`
	CodeHash            string       `db:"code_hash"`
	ClientId            int64        `db:"client_id"`
	Client              Client       `db:"-"`
	CodeChallenge       string       `db:"code_challenge"`
	CodeChallengeMethod string       `db:"code_challenge_method"`
	Scope               string       `db:"scope"`
	State               string       `db:"state"`
	Nonce               string       `db:"nonce"`
	RedirectURI         string       `db:"redirect_uri"`
	UserId              int64        `db:"user_id"`
	User                User         `db:"-"`
	IpAddress           string       `db:"ip_address"`
	UserAgent           string       `db:"user_agent"`
	ResponseMode        string       `db:"response_mode"`
	AuthenticatedAt     time.Time    `db:"authenticated_at"`
	SessionIdentifier   string       `db:"session_identifier"`
	AcrLevel            string       `db:"acr_level"`
	AuthMethods         string       `db:"auth_methods"`
	Used                bool         `db:"used"`
}

type RefreshToken struct {
	Id                      int64        `db:"id" fieldtag:"pk"`
	CreatedAt               sql.NullTime `db:"created_at"`
	UpdatedAt               sql.NullTime `db:"updated_at"`
	CodeId                  int64        `db:"code_id"`
	Code                    Code         `db:"-"`
	RefreshTokenJti         string       `db:"refresh_token_jti"`
	PreviousRefreshTokenJti string       `db:"previous_refresh_token_jti"`
	FirstRefreshTokenJti    string       `db:"first_refresh_token_jti"`
	SessionIdentifier       string       `db:"session_identifier"`
	RefreshTokenType        string       `db:"refresh_token_type"`
	Scope                   string       `db:"scope"`
	IssuedAt                sql.NullTime `db:"issued_at"`
	ExpiresAt               sql.NullTime `db:"expires_at"`
	MaxLifetime             sql.NullTime `db:"max_lifetime"`
	Revoked                 bool         `db:"revoked"`
}

type KeyPair struct {
	Id                int64        `db:"id" fieldtag:"pk"`
	CreatedAt         sql.NullTime `db:"created_at"`
	UpdatedAt         sql.NullTime `db:"updated_at"`
	State             string       `db:"state"`
	KeyIdentifier     string       `db:"key_identifier"`
	Type              string       `db:"type" fieldopt:"withquote"`
	Algorithm         string       `db:"algorithm" fieldopt:"withquote"`
	PrivateKeyPEM     []byte       `db:"private_key_pem"`
	PublicKeyPEM      []byte       `db:"public_key_pem"`
	PublicKeyASN1_DER []byte       `db:"public_key_asn1_der"`
	PublicKeyJWK      []byte       `db:"public_key_jwk"`
}

type Settings struct {
	Id                                        int64                `db:"id" fieldtag:"pk"`
	CreatedAt                                 sql.NullTime         `db:"created_at"`
	UpdatedAt                                 sql.NullTime         `db:"updated_at"`
	AppName                                   string               `db:"app_name"`
	Issuer                                    string               `db:"issuer"`
	UITheme                                   string               `db:"ui_theme"`
	PasswordPolicy                            enums.PasswordPolicy `db:"password_policy"`
	SelfRegistrationEnabled                   bool                 `db:"self_registration_enabled"`
	SelfRegistrationRequiresEmailVerification bool                 `db:"self_registration_requires_email_verification"`
	TokenExpirationInSeconds                  int                  `db:"token_expiration_in_seconds"`
	RefreshTokenOfflineIdleTimeoutInSeconds   int                  `db:"refresh_token_offline_idle_timeout_in_seconds"`
	RefreshTokenOfflineMaxLifetimeInSeconds   int                  `db:"refresh_token_offline_max_lifetime_in_seconds"`
	UserSessionIdleTimeoutInSeconds           int                  `db:"user_session_idle_timeout_in_seconds"`
	UserSessionMaxLifetimeInSeconds           int                  `db:"user_session_max_lifetime_in_seconds"`
	IncludeOpenIDConnectClaimsInAccessToken   bool                 `db:"include_open_id_connect_claims_in_access_token"`
	SessionAuthenticationKey                  []byte               `db:"session_authentication_key"`
	SessionEncryptionKey                      []byte               `db:"session_encryption_key"`
	AESEncryptionKey                          []byte               `db:"aes_encryption_key"`
	SMTPHost                                  string               `db:"smtp_host"`
	SMTPPort                                  int                  `db:"smtp_port"`
	SMTPUsername                              string               `db:"smtp_username"`
	SMTPPasswordEncrypted                     []byte               `db:"smtp_password_encrypted"`
	SMTPFromName                              string               `db:"smtp_from_name"`
	SMTPFromEmail                             string               `db:"smtp_from_email"`
	SMTPEncryption                            string               `db:"smtp_encryption"`
	SMTPEnabled                               bool                 `db:"smtp_enabled"`
	SMSProvider                               string               `db:"sms_provider"`
	SMSConfigEncrypted                        []byte               `db:"sms_config_encrypted"`
}

type PreRegistration struct {
	Id                        int64        `db:"id" fieldtag:"pk"`
	CreatedAt                 sql.NullTime `db:"created_at"`
	UpdatedAt                 sql.NullTime `db:"updated_at"`
	Email                     string       `db:"email"`
	PasswordHash              string       `db:"password_hash"`
	VerificationCodeEncrypted []byte       `db:"verification_code_encrypted"`
	VerificationCodeIssuedAt  sql.NullTime `db:"verification_code_issued_at"`
}

type Group struct {
	Id                   int64            `db:"id" fieldtag:"pk"`
	CreatedAt            sql.NullTime     `db:"created_at"`
	UpdatedAt            sql.NullTime     `db:"updated_at"`
	GroupIdentifier      string           `db:"group_identifier"`
	Description          string           `db:"description"`
	Users                []User           `db:"-"`
	Attributes           []GroupAttribute `db:"-"`
	Permissions          []Permission     `db:"-"`
	IncludeInIdToken     bool             `db:"include_in_id_token"`
	IncludeInAccessToken bool             `db:"include_in_access_token"`
}

type UserAttribute struct {
	Id                   int64        `db:"id" fieldtag:"pk"`
	CreatedAt            sql.NullTime `db:"created_at"`
	UpdatedAt            sql.NullTime `db:"updated_at"`
	Key                  string       `db:"key" fieldopt:"withquote"`
	Value                string       `db:"value" fieldopt:"withquote"`
	IncludeInIdToken     bool         `db:"include_in_id_token"`
	IncludeInAccessToken bool         `db:"include_in_access_token"`
	UserId               int64        `db:"user_id"`
	User                 User         `db:"-"`
}

type GroupAttribute struct {
	Id                   int64        `db:"id" fieldtag:"pk"`
	CreatedAt            sql.NullTime `db:"created_at"`
	UpdatedAt            sql.NullTime `db:"updated_at"`
	Key                  string       `db:"key" fieldopt:"withquote"`
	Value                string       `db:"value" fieldopt:"withquote"`
	IncludeInIdToken     bool         `db:"include_in_id_token"`
	IncludeInAccessToken bool         `db:"include_in_access_token"`
	GroupId              int64        `db:"group_id"`
	Group                Group        `db:"-"`
}

type HttpSession struct {
	Id        int64        `db:"id" fieldtag:"pk"`
	Data      string       `db:"data"`
	CreatedAt sql.NullTime `db:"created_at"`
	UpdatedAt sql.NullTime `db:"updated_at"`
	ExpiresOn sql.NullTime `db:"expires_on"`
}

type UserPermission struct {
	Id           int64        `db:"id" fieldtag:"pk"`
	CreatedAt    sql.NullTime `db:"created_at"`
	UpdatedAt    sql.NullTime `db:"updated_at"`
	UserId       int64        `db:"user_id"`
	PermissionId int64        `db:"permission_id"`
}

type ClientPermission struct {
	Id           int64        `db:"id" fieldtag:"pk"`
	CreatedAt    sql.NullTime `db:"created_at"`
	UpdatedAt    sql.NullTime `db:"updated_at"`
	ClientId     int64        `db:"client_id"`
	PermissionId int64        `db:"permission_id"`
}

type UserGroup struct {
	Id        int64        `db:"id" fieldtag:"pk"`
	CreatedAt sql.NullTime `db:"created_at"`
	UpdatedAt sql.NullTime `db:"updated_at"`
	UserId    int64        `db:"user_id"`
	GroupId   int64        `db:"group_id"`
}

type GroupPermission struct {
	Id           int64        `db:"id" fieldtag:"pk"`
	CreatedAt    sql.NullTime `db:"created_at"`
	UpdatedAt    sql.NullTime `db:"updated_at"`
	GroupId      int64        `db:"group_id"`
	PermissionId int64        `db:"permission_id"`
}
