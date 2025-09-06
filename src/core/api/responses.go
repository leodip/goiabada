package api

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/models"
)

type UserResponse struct {
	Id                            int64               `json:"id"`
	CreatedAt                     *time.Time          `json:"createdAt"`
	UpdatedAt                     *time.Time          `json:"updatedAt"`
	Enabled                       bool                `json:"enabled"`
	Subject                       uuid.UUID           `json:"subject"`
	Username                      string              `json:"username"`
	GivenName                     string              `json:"givenName"`
	MiddleName                    string              `json:"middleName"`
	FamilyName                    string              `json:"familyName"`
	Nickname                      string              `json:"nickname"`
	Website                       string              `json:"website"`
	Gender                        string              `json:"gender"`
	Email                         string              `json:"email"`
	EmailVerified                 bool                `json:"emailVerified"`
	ZoneInfoCountryName           string              `json:"zoneInfoCountryName"`
	ZoneInfo                      string              `json:"zoneInfo"`
	Locale                        string              `json:"locale"`
	BirthDate                     *time.Time          `json:"birthDate"`
	PhoneNumberCountryUniqueId    string              `json:"phoneNumberCountryUniqueId"`
	PhoneNumberCountryCallingCode string              `json:"phoneNumberCountryCallingCode"`
	PhoneNumber                   string              `json:"phoneNumber"`
	PhoneNumberVerified           bool                `json:"phoneNumberVerified"`
	AddressLine1                  string              `json:"addressLine1"`
	AddressLine2                  string              `json:"addressLine2"`
	AddressLocality               string              `json:"addressLocality"`
	AddressRegion                 string              `json:"addressRegion"`
	AddressPostalCode             string              `json:"addressPostalCode"`
	AddressCountry                string              `json:"addressCountry"`
	OTPEnabled                    bool                `json:"otpEnabled"`
	Groups                        []models.Group      `json:"groups"`
	Permissions                   []models.Permission `json:"permissions"`
	Attributes                    []UserAttributeResponse `json:"attributes"`
}

func ToUserResponse(user *models.User) *UserResponse {
	if user == nil {
		return nil
	}

	resp := &UserResponse{
		Id:                            user.Id,
		Enabled:                       user.Enabled,
		Subject:                       user.Subject,
		Username:                      user.Username,
		GivenName:                     user.GivenName,
		MiddleName:                    user.MiddleName,
		FamilyName:                    user.FamilyName,
		Nickname:                      user.Nickname,
		Website:                       user.Website,
		Gender:                        user.Gender,
		Email:                         user.Email,
		EmailVerified:                 user.EmailVerified,
		ZoneInfoCountryName:           user.ZoneInfoCountryName,
		ZoneInfo:                      user.ZoneInfo,
		Locale:                        user.Locale,
		PhoneNumberCountryUniqueId:    user.PhoneNumberCountryUniqueId,
		PhoneNumberCountryCallingCode: user.PhoneNumberCountryCallingCode,
		PhoneNumber:                   user.PhoneNumber,
		PhoneNumberVerified:           user.PhoneNumberVerified,
		AddressLine1:                  user.AddressLine1,
		AddressLine2:                  user.AddressLine2,
		AddressLocality:               user.AddressLocality,
		AddressRegion:                 user.AddressRegion,
		AddressPostalCode:             user.AddressPostalCode,
		AddressCountry:                user.AddressCountry,
		OTPEnabled:                    user.OTPEnabled,
		Groups:                        user.Groups,
		Permissions:                   user.Permissions,
		Attributes:                    ToUserAttributeResponses(user.Attributes),
	}

	if user.CreatedAt.Valid {
		resp.CreatedAt = &user.CreatedAt.Time
	}
	if user.UpdatedAt.Valid {
		resp.UpdatedAt = &user.UpdatedAt.Time
	}
	if user.BirthDate.Valid {
		resp.BirthDate = &user.BirthDate.Time
	}

	return resp
}

func ToUserResponses(users []models.User) []UserResponse {
	if users == nil {
		return nil
	}

	responses := make([]UserResponse, len(users))
	for i, user := range users {
		resp := ToUserResponse(&user)
		if resp != nil {
			responses[i] = *resp
		}
	}
	return responses
}

func (resp *UserResponse) ToUser() *models.User {
	if resp == nil {
		return nil
	}

	user := &models.User{
		Id:                            resp.Id,
		Enabled:                       resp.Enabled,
		Subject:                       resp.Subject,
		Username:                      resp.Username,
		GivenName:                     resp.GivenName,
		MiddleName:                    resp.MiddleName,
		FamilyName:                    resp.FamilyName,
		Nickname:                      resp.Nickname,
		Website:                       resp.Website,
		Gender:                        resp.Gender,
		Email:                         resp.Email,
		EmailVerified:                 resp.EmailVerified,
		ZoneInfoCountryName:           resp.ZoneInfoCountryName,
		ZoneInfo:                      resp.ZoneInfo,
		Locale:                        resp.Locale,
		PhoneNumberCountryUniqueId:    resp.PhoneNumberCountryUniqueId,
		PhoneNumberCountryCallingCode: resp.PhoneNumberCountryCallingCode,
		PhoneNumber:                   resp.PhoneNumber,
		PhoneNumberVerified:           resp.PhoneNumberVerified,
		AddressLine1:                  resp.AddressLine1,
		AddressLine2:                  resp.AddressLine2,
		AddressLocality:               resp.AddressLocality,
		AddressRegion:                 resp.AddressRegion,
		AddressPostalCode:             resp.AddressPostalCode,
		AddressCountry:                resp.AddressCountry,
		OTPEnabled:                    resp.OTPEnabled,
		Groups:                        resp.Groups,
		Permissions:                   resp.Permissions,
	}

	if resp.CreatedAt != nil {
		user.CreatedAt = sql.NullTime{Time: *resp.CreatedAt, Valid: true}
	}
	if resp.UpdatedAt != nil {
		user.UpdatedAt = sql.NullTime{Time: *resp.UpdatedAt, Valid: true}
	}
	if resp.BirthDate != nil {
		user.BirthDate = sql.NullTime{Time: *resp.BirthDate, Valid: true}
	}

	if resp.Attributes != nil {
		user.Attributes = make([]models.UserAttribute, len(resp.Attributes))
		for i, attrResp := range resp.Attributes {
			if attr := attrResp.ToUserAttribute(); attr != nil {
				user.Attributes[i] = *attr
			}
		}
	}

	return user
}

type UserAttributeResponse struct {
	Id                   int64      `json:"id"`
	CreatedAt            *time.Time `json:"createdAt"`
	UpdatedAt            *time.Time `json:"updatedAt"`
	Key                  string     `json:"key"`
	Value                string     `json:"value"`
	IncludeInIdToken     bool       `json:"includeInIdToken"`
	IncludeInAccessToken bool       `json:"includeInAccessToken"`
	UserId               int64      `json:"userId"`
}

func ToUserAttributeResponse(attr *models.UserAttribute) *UserAttributeResponse {
	if attr == nil {
		return nil
	}

	resp := &UserAttributeResponse{
		Id:                   attr.Id,
		Key:                  attr.Key,
		Value:                attr.Value,
		IncludeInIdToken:     attr.IncludeInIdToken,
		IncludeInAccessToken: attr.IncludeInAccessToken,
		UserId:               attr.UserId,
	}

	if attr.CreatedAt.Valid {
		resp.CreatedAt = &attr.CreatedAt.Time
	}
	if attr.UpdatedAt.Valid {
		resp.UpdatedAt = &attr.UpdatedAt.Time
	}

	return resp
}

func ToUserAttributeResponses(attrs []models.UserAttribute) []UserAttributeResponse {
	if attrs == nil {
		return nil
	}

	responses := make([]UserAttributeResponse, len(attrs))
	for i, attr := range attrs {
		resp := ToUserAttributeResponse(&attr)
		if resp != nil {
			responses[i] = *resp
		}
	}
	return responses
}

func (resp *UserAttributeResponse) ToUserAttribute() *models.UserAttribute {
	if resp == nil {
		return nil
	}

	attr := &models.UserAttribute{
		Id:                   resp.Id,
		Key:                  resp.Key,
		Value:                resp.Value,
		IncludeInIdToken:     resp.IncludeInIdToken,
		IncludeInAccessToken: resp.IncludeInAccessToken,
		UserId:               resp.UserId,
	}

	if resp.CreatedAt != nil {
		attr.CreatedAt = sql.NullTime{Time: *resp.CreatedAt, Valid: true}
	}
	if resp.UpdatedAt != nil {
		attr.UpdatedAt = sql.NullTime{Time: *resp.UpdatedAt, Valid: true}
	}

	return attr
}

type SearchUsersResponse struct {
	Users []UserResponse `json:"users"`
	Total int            `json:"total"`
	Page  int            `json:"page"`
	Size  int            `json:"size"`
	Query string         `json:"query"`
}

type GetUserResponse struct {
	User UserResponse `json:"user"`
}

type CreateUserResponse struct {
	User UserResponse `json:"user"`
}

type UpdateUserResponse struct {
	User UserResponse `json:"user"`
}

type GetUserAttributesResponse struct {
	Attributes []UserAttributeResponse `json:"attributes"`
}

type GetUserAttributeResponse struct {
	Attribute UserAttributeResponse `json:"attribute"`
}

type CreateUserAttributeResponse struct {
	Attribute UserAttributeResponse `json:"attribute"`
}

type UpdateUserAttributeResponse struct {
	Attribute UserAttributeResponse `json:"attribute"`
}

type SuccessResponse struct {
	Success bool `json:"success"`
}

type ErrorResponse struct {
	Error struct {
		Message string `json:"message"`
		Code    string `json:"code"`
	} `json:"error"`
}

type UserSessionResponse struct {
	Id                          int64      `json:"id"`
	CreatedAt                   *time.Time `json:"createdAt"`
	UpdatedAt                   *time.Time `json:"updatedAt"`
	SessionIdentifier           string     `json:"sessionIdentifier"`
	Started                     *time.Time `json:"started"`
	LastAccessed                *time.Time `json:"lastAccessed"`
	AuthMethods                 string     `json:"authMethods"`
	AcrLevel                    string     `json:"acrLevel"`
	AuthTime                    *time.Time `json:"authTime"`
	IpAddress                   string     `json:"ipAddress"`
	DeviceName                  string     `json:"deviceName"`
	DeviceType                  string     `json:"deviceType"`
	DeviceOS                    string     `json:"deviceOS"`
	Level2AuthConfigHasChanged  bool       `json:"level2AuthConfigHasChanged"`
	UserId                      int64      `json:"userId"`
}

func ToUserSessionResponse(session *models.UserSession) *UserSessionResponse {
	if session == nil {
		return nil
	}

	resp := &UserSessionResponse{
		Id:                         session.Id,
		SessionIdentifier:          session.SessionIdentifier,
		AuthMethods:                session.AuthMethods,
		AcrLevel:                   session.AcrLevel,
		IpAddress:                  session.IpAddress,
		DeviceName:                 session.DeviceName,
		DeviceType:                 session.DeviceType,
		DeviceOS:                   session.DeviceOS,
		Level2AuthConfigHasChanged: session.Level2AuthConfigHasChanged,
		UserId:                     session.UserId,
	}

	if session.CreatedAt.Valid {
		resp.CreatedAt = &session.CreatedAt.Time
	}
	if session.UpdatedAt.Valid {
		resp.UpdatedAt = &session.UpdatedAt.Time
	}
	if !session.Started.IsZero() {
		resp.Started = &session.Started
	}
	if !session.LastAccessed.IsZero() {
		resp.LastAccessed = &session.LastAccessed
	}
	if !session.AuthTime.IsZero() {
		resp.AuthTime = &session.AuthTime
	}

	return resp
}

type GetUserSessionResponse struct {
	Session UserSessionResponse `json:"session"`
}

type UserConsentResponse struct {
	Id                int64      `json:"id"`
	CreatedAt         *time.Time `json:"createdAt"`
	UpdatedAt         *time.Time `json:"updatedAt"`
	ClientId          int64      `json:"clientId"`
	UserId            int64      `json:"userId"`
	Scope             string     `json:"scope"`
	GrantedAt         *time.Time `json:"grantedAt"`
	ClientIdentifier  string     `json:"clientIdentifier"`
	ClientDescription string     `json:"clientDescription"`
}

func ToUserConsentResponse(consent *models.UserConsent) *UserConsentResponse {
	if consent == nil {
		return nil
	}

	resp := &UserConsentResponse{
		Id:       consent.Id,
		ClientId: consent.ClientId,
		UserId:   consent.UserId,
		Scope:    consent.Scope,
	}

	if consent.CreatedAt.Valid {
		resp.CreatedAt = &consent.CreatedAt.Time
	}
	if consent.UpdatedAt.Valid {
		resp.UpdatedAt = &consent.UpdatedAt.Time
	}
	if consent.GrantedAt.Valid {
		resp.GrantedAt = &consent.GrantedAt.Time
	}

	// Include client information if loaded
	if consent.Client.Id != 0 {
		resp.ClientIdentifier = consent.Client.ClientIdentifier
		resp.ClientDescription = consent.Client.Description
	}

	return resp
}

func ToUserConsentResponses(consents []models.UserConsent) []UserConsentResponse {
	if consents == nil {
		return nil
	}

	responses := make([]UserConsentResponse, len(consents))
	for i, consent := range consents {
		resp := ToUserConsentResponse(&consent)
		if resp != nil {
			responses[i] = *resp
		}
	}
	return responses
}

type GetUserConsentsResponse struct {
	Consents []UserConsentResponse `json:"consents"`
}

type GroupResponse struct {
	Id               int64  `json:"id"`
	GroupIdentifier  string `json:"groupIdentifier"`
	Description      string `json:"description"`
	IncludeInIdToken bool   `json:"includeInIdToken"`
}

func ToGroupResponse(group *models.Group) *GroupResponse {
	if group == nil {
		return nil
	}

	return &GroupResponse{
		Id:               group.Id,
		GroupIdentifier:  group.GroupIdentifier,
		Description:      group.Description,
		IncludeInIdToken: group.IncludeInIdToken,
	}
}

func ToGroupResponses(groups []models.Group) []GroupResponse {
	if groups == nil {
		return nil
	}

	responses := make([]GroupResponse, len(groups))
	for i, group := range groups {
		resp := ToGroupResponse(&group)
		if resp != nil {
			responses[i] = *resp
		}
	}
	return responses
}

type GetGroupsResponse struct {
	Groups []GroupResponse `json:"groups"`
}

type GetUserGroupsResponse struct {
	User   UserResponse    `json:"user"`
	Groups []GroupResponse `json:"groups"`
}

type PermissionResponse struct {
	Id                   int64  `json:"id"`
	PermissionIdentifier string `json:"permissionIdentifier"`
	Description          string `json:"description"`
	ResourceId           int64  `json:"resourceId"`
	Resource             ResourceResponse `json:"resource"`
}

type ResourceResponse struct {
	Id                 int64  `json:"id"`
	ResourceIdentifier string `json:"resourceIdentifier"`
	Description        string `json:"description"`
}

func ToPermissionResponse(perm *models.Permission) *PermissionResponse {
	if perm == nil {
		return nil
	}
	return &PermissionResponse{
		Id:                   perm.Id,
		PermissionIdentifier: perm.PermissionIdentifier,
		Description:          perm.Description,
		ResourceId:           perm.ResourceId,
		Resource:             *ToResourceResponse(&perm.Resource),
	}
}

func ToPermissionResponses(perms []models.Permission) []PermissionResponse {
	if perms == nil {
		return nil
	}
	responses := make([]PermissionResponse, len(perms))
	for i, perm := range perms {
		resp := ToPermissionResponse(&perm)
		if resp != nil {
			responses[i] = *resp
		}
	}
	return responses
}

func ToResourceResponse(resource *models.Resource) *ResourceResponse {
	if resource == nil {
		return nil
	}
	return &ResourceResponse{
		Id:                 resource.Id,
		ResourceIdentifier: resource.ResourceIdentifier,
		Description:        resource.Description,
	}
}

func ToResourceResponses(resources []models.Resource) []ResourceResponse {
	if resources == nil {
		return nil
	}
	responses := make([]ResourceResponse, len(resources))
	for i, resource := range resources {
		resp := ToResourceResponse(&resource)
		if resp != nil {
			responses[i] = *resp
		}
	}
	return responses
}

type GetUserPermissionsResponse struct {
	User        UserResponse         `json:"user"`
	Permissions []PermissionResponse `json:"permissions"`
}

type GetResourcesResponse struct {
	Resources []ResourceResponse `json:"resources"`
}

type GetPermissionsByResourceResponse struct {
	Permissions []PermissionResponse `json:"permissions"`
}