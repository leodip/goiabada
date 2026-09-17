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

// ToSessionOwnerResponse projects a user down to the five fields a session page shows about
// whoever a listed session belongs to. It is not ToUserResponse narrowed for payload: the
// client-sessions endpoint is the only caller and it is reached with the clients scopes alone,
// so the fields left out are left out because that caller is not entitled to them (#373).
func ToSessionOwnerResponse(user *models.User) *api.SessionOwnerResponse {
	if user == nil {
		return nil
	}

	return &api.SessionOwnerResponse{
		Id:         user.Id,
		Email:      user.Email,
		GivenName:  user.GivenName,
		MiddleName: user.MiddleName,
		FamilyName: user.FamilyName,
	}
}

func ToSessionOwnerResponses(users []models.User) []api.SessionOwnerResponse {
	if users == nil {
		return nil
	}

	responses := make([]api.SessionOwnerResponse, len(users))
	for i, user := range users {
		resp := ToSessionOwnerResponse(&user)
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

// ToUserSessionDetailResponse maps a session for the three list endpoints: the base response
// plus whether the session is the caller's own and the identifiers of the clients it
// authorized.
//
// currentSid is the "sid" claim of the caller's access token, empty when the token carries
// none: client_credentials tokens and offline grants have it suppressed, and a caller holding
// one is correctly told that none of the sessions is its own. Computing it here rather than at
// each producer is what keeps the field meaning the same thing on all three endpoints; it was
// assigned at one of the three, so the other two published a constant false (#373).
//
// session.Clients is read as already loaded and the database is never touched: the caller
// hydrates the whole list in one query before calling this, which is why the mapping belongs in
// this package (#350).
func ToUserSessionDetailResponse(session *models.UserSession, currentSid string) *api.UserSessionDetailResponse {
	base := ToUserSessionResponse(session)
	if base == nil {
		return nil
	}

	// Never nil: the schema declares clientIdentifiers a required array, and a nil slice
	// marshals to null, which is not an empty array to anything reading the document.
	clientIdentifiers := make([]string, 0, len(session.Clients))
	for _, usc := range session.Clients {
		clientIdentifiers = append(clientIdentifiers, usc.Client.ClientIdentifier)
	}

	return &api.UserSessionDetailResponse{
		UserSessionResponse: *base,
		IsCurrent:           currentSid != "" && session.SessionIdentifier == currentSid,
		ClientIdentifiers:   clientIdentifiers,
	}
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
		Id:                    resource.Id,
		ResourceIdentifier:    resource.ResourceIdentifier,
		Description:           resource.Description,
		IsSystemLevelResource: resource.IsSystemLevelResource(),
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

// toRedirectURIResponses and toWebOriginResponses are unexported because ToClientResponse is their
// only caller: these two shapes reach the wire nested inside a client and nowhere else.
//
// Both preserve nil rather than returning an empty slice, because a client loaded without its
// collections puts "redirectURIs":null on the wire and a client loaded with an empty one puts [],
// and a consumer has to tell "not loaded" from "none" (#350).
func toRedirectURIResponses(uris []models.RedirectURI) []api.RedirectURIResponse {
	if uris == nil {
		return nil
	}
	responses := make([]api.RedirectURIResponse, len(uris))
	for i, uri := range uris {
		responses[i] = api.RedirectURIResponse{
			Id:       uri.Id,
			URI:      uri.URI,
			ClientId: uri.ClientId,
		}
		if uri.CreatedAt.Valid {
			responses[i].CreatedAt = &uris[i].CreatedAt.Time
		}
	}
	return responses
}

func toWebOriginResponses(origins []models.WebOrigin) []api.WebOriginResponse {
	if origins == nil {
		return nil
	}
	responses := make([]api.WebOriginResponse, len(origins))
	for i, origin := range origins {
		responses[i] = api.WebOriginResponse{
			Id:       origin.Id,
			Origin:   origin.Origin,
			ClientId: origin.ClientId,
		}
		if origin.CreatedAt.Valid {
			responses[i].CreatedAt = &origins[i].CreatedAt.Time
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
		RedirectURIs:                            toRedirectURIResponses(client.RedirectURIs),
		WebOrigins:                              toWebOriginResponses(client.WebOrigins),
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
