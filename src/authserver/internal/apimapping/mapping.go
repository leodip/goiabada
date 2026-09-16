// Package apimapping owns the auth server's mapping from persistence models to the
// wire types in core/api. It lives here, and not beside the types it produces, so that
// core/api declares JSON and nothing else: the kernel's wire contract must not depend on
// core/models, and the admin console must be able to decode a response without linking
// the persistence layer (#350).
package apimapping

import (
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/models"
)

func ToUserResponse(user *models.User) *api.UserResponse {
	if user == nil {
		return nil
	}

	resp := &api.UserResponse{
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

func ToUserResponses(users []models.User) []api.UserResponse {
	if users == nil {
		return nil
	}

	responses := make([]api.UserResponse, len(users))
	for i, user := range users {
		resp := ToUserResponse(&user)
		if resp != nil {
			responses[i] = *resp
		}
	}
	return responses
}

func ToUserAttributeResponse(attr *models.UserAttribute) *api.UserAttributeResponse {
	if attr == nil {
		return nil
	}

	resp := &api.UserAttributeResponse{
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

func ToUserAttributeResponses(attrs []models.UserAttribute) []api.UserAttributeResponse {
	if attrs == nil {
		return nil
	}

	responses := make([]api.UserAttributeResponse, len(attrs))
	for i, attr := range attrs {
		resp := ToUserAttributeResponse(&attr)
		if resp != nil {
			responses[i] = *resp
		}
	}
	return responses
}

func ToUserSessionResponse(session *models.UserSession) *api.UserSessionResponse {
	if session == nil {
		return nil
	}

	resp := &api.UserSessionResponse{
		Id:                session.Id,
		SessionIdentifier: session.SessionIdentifier,
		AuthMethods:       session.AuthMethods,
		AcrLevel:          session.AcrLevel,
		IpAddress:         session.IpAddress,
		DeviceName:        session.DeviceName,
		DeviceType:        session.DeviceType,
		DeviceOS:          session.DeviceOS,
		UserAgent:         session.UserAgent,
		UserId:            session.UserId,
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

func ToUserConsentResponse(consent *models.UserConsent) *api.UserConsentResponse {
	if consent == nil {
		return nil
	}

	resp := &api.UserConsentResponse{
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

func ToUserConsentResponses(consents []models.UserConsent) []api.UserConsentResponse {
	if consents == nil {
		return nil
	}

	responses := make([]api.UserConsentResponse, len(consents))
	for i, consent := range consents {
		resp := ToUserConsentResponse(&consent)
		if resp != nil {
			responses[i] = *resp
		}
	}
	return responses
}

func ToGroupResponse(group *models.Group, memberCount int) *api.GroupResponse {
	if group == nil {
		return nil
	}

	resp := &api.GroupResponse{
		Id:                   group.Id,
		GroupIdentifier:      group.GroupIdentifier,
		Description:          group.Description,
		IncludeInIdToken:     group.IncludeInIdToken,
		IncludeInAccessToken: group.IncludeInAccessToken,
		MemberCount:          memberCount,
	}

	if group.CreatedAt.Valid {
		resp.CreatedAt = &group.CreatedAt.Time
	}
	if group.UpdatedAt.Valid {
		resp.UpdatedAt = &group.UpdatedAt.Time
	}

	return resp
}

func ToGroupResponses(groups []models.Group, memberCounts map[int64]int) []api.GroupResponse {
	if groups == nil {
		return []api.GroupResponse{}
	}

	if len(groups) == 0 {
		return []api.GroupResponse{}
	}

	responses := make([]api.GroupResponse, 0, len(groups))
	for _, group := range groups {
		memberCount := 0
		if memberCounts != nil {
			memberCount = memberCounts[group.Id]
		}
		resp := ToGroupResponse(&group, memberCount)
		if resp != nil {
			responses = append(responses, *resp)
		}
	}
	return responses
}

func ToPermissionResponse(perm *models.Permission) *api.PermissionResponse {
	if perm == nil {
		return nil
	}
	return &api.PermissionResponse{
		Id:                   perm.Id,
		PermissionIdentifier: perm.PermissionIdentifier,
		Description:          perm.Description,
		ResourceId:           perm.ResourceId,
		Resource:             *ToResourceResponse(&perm.Resource),
	}
}

func ToPermissionResponses(perms []models.Permission) []api.PermissionResponse {
	if perms == nil {
		return nil
	}
	responses := make([]api.PermissionResponse, len(perms))
	for i, perm := range perms {
		resp := ToPermissionResponse(&perm)
		if resp != nil {
			responses[i] = *resp
		}
	}
	return responses
}

func ToResourceResponse(resource *models.Resource) *api.ResourceResponse {
	if resource == nil {
		return nil
	}
	return &api.ResourceResponse{
		Id:                 resource.Id,
		ResourceIdentifier: resource.ResourceIdentifier,
		Description:        resource.Description,
	}
}

func ToResourceResponses(resources []models.Resource) []api.ResourceResponse {
	if resources == nil {
		return nil
	}
	responses := make([]api.ResourceResponse, len(resources))
	for i, resource := range resources {
		resp := ToResourceResponse(&resource)
		if resp != nil {
			responses[i] = *resp
		}
	}
	return responses
}

func ToGroupAttributeResponse(attr *models.GroupAttribute) *api.GroupAttributeResponse {
	if attr == nil {
		return nil
	}

	resp := &api.GroupAttributeResponse{
		Id:                   attr.Id,
		Key:                  attr.Key,
		Value:                attr.Value,
		IncludeInIdToken:     attr.IncludeInIdToken,
		IncludeInAccessToken: attr.IncludeInAccessToken,
		GroupId:              attr.GroupId,
	}

	if attr.CreatedAt.Valid {
		resp.CreatedAt = &attr.CreatedAt.Time
	}
	if attr.UpdatedAt.Valid {
		resp.UpdatedAt = &attr.UpdatedAt.Time
	}

	return resp
}

func ToGroupAttributeResponses(attrs []models.GroupAttribute) []api.GroupAttributeResponse {
	if attrs == nil {
		return nil
	}

	responses := make([]api.GroupAttributeResponse, len(attrs))
	for i, attr := range attrs {
		resp := ToGroupAttributeResponse(&attr)
		if resp != nil {
			responses[i] = *resp
		}
	}
	return responses
}

func ToClientResponse(client *models.Client) *api.ClientResponse {
	if client == nil {
		return nil
	}

	resp := &api.ClientResponse{
		Id:                                      client.Id,
		ClientIdentifier:                        client.ClientIdentifier,
		Description:                             client.Description,
		WebsiteURL:                              client.WebsiteURL,
		DisplayName:                             client.DisplayName,
		Enabled:                                 client.Enabled,
		ConsentRequired:                         client.ConsentRequired,
		CreatedViaDCR:                           client.CreatedViaDCR,
		ShowLogo:                                client.ShowLogo,
		ShowDisplayName:                         client.ShowDisplayName,
		ShowDescription:                         client.ShowDescription,
		ShowWebsiteURL:                          client.ShowWebsiteURL,
		IsPublic:                                client.IsPublic,
		IsSystemLevelClient:                     client.IsSystemLevelClient(),
		AuthorizationCodeEnabled:                client.AuthorizationCodeEnabled,
		ClientCredentialsEnabled:                client.ClientCredentialsEnabled,
		PKCERequired:                            client.PKCERequired,
		ImplicitGrantEnabled:                    client.ImplicitGrantEnabled,
		ResourceOwnerPasswordCredentialsEnabled: client.ResourceOwnerPasswordCredentialsEnabled,
		TokenExpirationInSeconds:                client.TokenExpirationInSeconds,
		RefreshTokenOfflineIdleTimeoutInSeconds: client.RefreshTokenOfflineIdleTimeoutInSeconds,
		RefreshTokenOfflineMaxLifetimeInSeconds: client.RefreshTokenOfflineMaxLifetimeInSeconds,
		IncludeOpenIDConnectClaimsInAccessToken: client.IncludeOpenIDConnectClaimsInAccessToken,
		IncludeOpenIDConnectClaimsInIdToken:     client.IncludeOpenIDConnectClaimsInIdToken,
		DefaultAcrLevel:                         string(client.DefaultAcrLevel),
		RedirectURIs:                            client.RedirectURIs,
		WebOrigins:                              client.WebOrigins,
	}

	if client.CreatedAt.Valid {
		resp.CreatedAt = &client.CreatedAt.Time
	}
	if client.UpdatedAt.Valid {
		resp.UpdatedAt = &client.UpdatedAt.Time
	}

	// Client secret should be set directly by the handler after decryption
	// We don't decrypt here since we don't have access to settings

	return resp
}

func ToClientResponses(clients []models.Client) []api.ClientResponse {
	if clients == nil {
		return []api.ClientResponse{}
	}

	if len(clients) == 0 {
		return []api.ClientResponse{}
	}

	responses := make([]api.ClientResponse, 0, len(clients))
	for _, client := range clients {
		resp := ToClientResponse(&client)
		if resp != nil {
			responses = append(responses, *resp)
		}
	}
	return responses
}
