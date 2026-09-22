package apiclient

import (
	"context"

	"github.com/leodip/goiabada/core/api"
)

// The table wire_characterization_test.go drives. One row per ApiClient method, in the order the
// files declare them. See that file's header for what a row pins and what it deliberately does
// not.

// The request values the rows hand to the methods that take one. Each carries a distinctive field
// so a row that sent the wrong value would not compare equal.
var (
	charPictureBytes = []byte("the-picture-bytes")

	charUpdateUserProfile   = &api.UpdateUserProfileRequest{Username: "jdoe"}
	charUpdateUserAddress   = &api.UpdateUserAddressRequest{AddressLine1: "1 Main Street"}
	charUpdateAccountEmail  = &api.UpdateAccountEmailRequest{Email: "jane@example.com"}
	charUpdateAccountPhone  = &api.UpdateAccountPhoneRequest{PhoneNumber: "5551234"}
	charUpdateAccountPwd    = &api.UpdateAccountPasswordRequest{CurrentPassword: "old", NewPassword: "new"}
	charVerifyAccountEmail  = &api.VerifyAccountEmailRequest{VerificationCode: "123456"}
	charUpdateAccountOTP    = &api.UpdateAccountOTPRequest{Enabled: true, OtpCode: "654321"}
	charAccountLogout       = &api.AccountLogoutRequest{PostLogoutRedirectUri: "https://console.example.com/"}
	charUpdateAuditSettings = &api.UpdateSettingsAuditLogsRequest{AuditLogRetentionDays: 30}

	charCreateClient      = &api.CreateClientRequest{ClientIdentifier: "a-new-client"}
	charUpdateClient      = &api.UpdateClientSettingsRequest{ClientIdentifier: "a-client"}
	charUpdateClientAuth  = &api.UpdateClientAuthenticationRequest{IsPublic: true}
	charUpdateClientFlows = &api.UpdateClientOAuth2FlowsRequest{AuthorizationCodeEnabled: true}
	charUpdateClientRedir = &api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{"https://app.example.com/cb"}}
	charUpdateClientOrig  = &api.UpdateClientWebOriginsRequest{WebOrigins: []string{"https://app.example.com"}}
	charUpdateClientToken = &api.UpdateClientTokensRequest{TokenExpirationInSeconds: 300}
	charUpdateClientPerms = &api.UpdateClientPermissionsRequest{PermissionIds: []int64{8}}

	charCreateGroupAttr = &api.CreateGroupAttributeRequest{Key: "department", Value: "sales"}
	charUpdateGroupAttr = &api.UpdateGroupAttributeRequest{Key: "department", Value: "support"}
	charCreateGroup     = &api.CreateGroupRequest{GroupIdentifier: "a-new-group"}
	charUpdateGroup     = &api.UpdateGroupRequest{GroupIdentifier: "a-group"}
	charUpdateUserGrps  = &api.UpdateUserGroupsRequest{GroupIds: []int64{5}}
	charUpdateGroupPerm = &api.UpdateGroupPermissionsRequest{PermissionIds: []int64{8}}
	charUpdateUserPerm  = &api.UpdateUserPermissionsRequest{PermissionIds: []int64{8}}
	charUpdateResPerms  = &api.UpdateResourcePermissionsRequest{Permissions: []api.ResourcePermissionUpsert{}}

	charUpdateUserPhone = &api.UpdateUserPhoneRequest{PhoneNumber: "5555678"}
	charCreateResource  = &api.CreateResourceRequest{ResourceIdentifier: "a-new-resource"}
	charUpdateResource  = &api.UpdateResourceRequest{ResourceIdentifier: "a-resource"}

	charUpdateEmailSettings    = &api.UpdateSettingsEmailRequest{SMTPHost: "smtp.example.com"}
	charSendTestEmail          = &api.SendTestEmailRequest{To: "jane@example.com"}
	charUpdateGeneralSettings  = &api.UpdateSettingsGeneralRequest{AppName: "Goiabada"}
	charUpdateSessionsSettings = &api.UpdateSettingsSessionsRequest{UserSessionIdleTimeoutInSeconds: 900}
	charUpdateTokensSettings   = &api.UpdateSettingsTokensRequest{TokenExpirationInSeconds: 300}
	charUpdateUIThemeSettings  = &api.UpdateSettingsUIThemeRequest{UITheme: "dark"}

	charCreateUserAttr = &api.CreateUserAttributeRequest{Key: "team", Value: "green"}
	charUpdateUserAttr = &api.UpdateUserAttributeRequest{Key: "team", Value: "blue"}
	charCreateUser     = &api.CreateUserAdminRequest{Email: "new@example.com"}
	charUpdateUserMail = &api.UpdateUserEmailRequest{Email: "jane@example.com"}
	charUpdateUserPwd  = &api.UpdateUserPasswordRequest{NewPassword: "a-new-password"}
	charUpdateUserOTP  = &api.UpdateUserOTPRequest{Enabled: false}
)

const (
	charJSON      = "application/json"
	charMultipart = "multipart/form-data; boundary="
)

func wireCharacterization() []wireCase {
	return []wireCase{
		// --- account_client.go ------------------------------------------------------------
		{
			name: "GetAccountProfile",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetAccountProfile(ctx, charAccessToken)
				if err != nil {
					return nil, err
				}
				return got.Id, nil
			},
			verb: "GET", path: "/api/v1/account/profile", contentType: charJSON,
			successStatus: 200, reply: `{"user":{"id":42}}`, want: int64(42),
		},
		{
			name: "UpdateAccountProfile",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UpdateAccountProfile(ctx, charAccessToken, charUpdateUserProfile)
				if err != nil {
					return nil, err
				}
				return got.Id, nil
			},
			verb: "PUT", path: "/api/v1/account/profile", contentType: charJSON,
			bodyOf:        charUpdateUserProfile,
			successStatus: 200, reply: `{"user":{"id":42}}`, want: int64(42),
		},
		{
			name: "UpdateAccountEmail",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UpdateAccountEmail(ctx, charAccessToken, charUpdateAccountEmail)
				if err != nil {
					return nil, err
				}
				return got.Email, nil
			},
			verb: "PUT", path: "/api/v1/account/email", contentType: charJSON,
			bodyOf:        charUpdateAccountEmail,
			successStatus: 200, reply: `{"user":{"email":"jane@example.com"}}`, want: "jane@example.com",
		},
		{
			name: "UpdateAccountPhone",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UpdateAccountPhone(ctx, charAccessToken, charUpdateAccountPhone)
				if err != nil {
					return nil, err
				}
				return got.PhoneNumber, nil
			},
			verb: "PUT", path: "/api/v1/account/phone", contentType: charJSON,
			bodyOf:        charUpdateAccountPhone,
			successStatus: 200, reply: `{"user":{"phoneNumber":"5551234"}}`, want: "5551234",
		},
		{
			name: "UpdateAccountAddress",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UpdateAccountAddress(ctx, charAccessToken, charUpdateUserAddress)
				if err != nil {
					return nil, err
				}
				return got.AddressLine1, nil
			},
			verb: "PUT", path: "/api/v1/account/address", contentType: charJSON,
			bodyOf:        charUpdateUserAddress,
			successStatus: 200, reply: `{"user":{"addressLine1":"1 Main Street"}}`, want: "1 Main Street",
		},
		{
			name: "UpdateAccountPassword",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UpdateAccountPassword(ctx, charAccessToken, charUpdateAccountPwd)
				if err != nil {
					return nil, err
				}
				return got.Id, nil
			},
			verb: "PUT", path: "/api/v1/account/password", contentType: charJSON,
			bodyOf:        charUpdateAccountPwd,
			successStatus: 200, reply: `{"user":{"id":42}}`, want: int64(42),
		},
		{
			name: "SendAccountEmailVerification",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.SendAccountEmailVerification(ctx, charAccessToken)
				if err != nil {
					return nil, err
				}
				return got.EmailDestination, nil
			},
			verb: "POST", path: "/api/v1/account/email/verification/send", contentType: charJSON,
			body:          `{}`,
			successStatus: 200, reply: `{"emailVerificationSent":true,"emailDestination":"jane@example.com"}`,
			want: "jane@example.com",
		},
		{
			name: "VerifyAccountEmail",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.VerifyAccountEmail(ctx, charAccessToken, charVerifyAccountEmail)
				if err != nil {
					return nil, err
				}
				return got.EmailVerified, nil
			},
			verb: "POST", path: "/api/v1/account/email/verification", contentType: charJSON,
			bodyOf:        charVerifyAccountEmail,
			successStatus: 200, reply: `{"user":{"emailVerified":true}}`, want: true,
		},
		{
			name: "GetAccountOTPEnrollment",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetAccountOTPEnrollment(ctx, charAccessToken)
				if err != nil {
					return nil, err
				}
				return got.SecretKey, nil
			},
			verb: "GET", path: "/api/v1/account/otp/enrollment", contentType: charJSON,
			successStatus: 200, reply: `{"secretKey":"ABCDEF","base64Image":"aW1n"}`, want: "ABCDEF",
		},
		{
			name: "UpdateAccountOTP",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UpdateAccountOTP(ctx, charAccessToken, charUpdateAccountOTP)
				if err != nil {
					return nil, err
				}
				return got.OTPEnabled, nil
			},
			verb: "PUT", path: "/api/v1/account/otp", contentType: charJSON,
			bodyOf:        charUpdateAccountOTP,
			successStatus: 200, reply: `{"user":{"otpEnabled":true}}`, want: true,
		},
		{
			name: "CreateAccountLogoutRequest",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				form, _, err := c.CreateAccountLogoutRequest(ctx, charAccessToken, charAccountLogout)
				if err != nil {
					return nil, err
				}
				return form.Endpoint, nil
			},
			verb: "POST", path: "/api/v1/account/logout-request", contentType: charJSON,
			bodyOf: charAccountLogout, anySuccess2xx: true,
			reply: `{"method":"POST","endpoint":"https://auth.example.com/auth/logout","params":{"state":"a-state"}}`,
			want:  "https://auth.example.com/auth/logout",
		},
		{
			name: "GetAccountConsents",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetAccountConsents(ctx, charAccessToken)
				if err != nil {
					return nil, err
				}
				return got[0].Scope, nil
			},
			verb: "GET", path: "/api/v1/account/consents", contentType: charJSON,
			successStatus: 200, reply: `{"consents":[{"id":13,"scope":"openid profile"}]}`,
			want: "openid profile",
		},
		{
			name: "RevokeAccountConsent",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				return nil, c.RevokeAccountConsent(ctx, charAccessToken, 13)
			},
			verb: "DELETE", path: "/api/v1/account/consents/13", contentType: charJSON,
			successStatus: 200, reply: `{}`,
		},
		{
			name: "GetAccountProfilePicture",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetAccountProfilePicture(ctx, charAccessToken)
				if err != nil {
					return nil, err
				}
				return got.PictureUrl, nil
			},
			verb: "GET", path: "/api/v1/account/profile-picture", contentType: charJSON,
			successStatus: 200, reply: `{"hasPicture":true,"pictureUrl":"/account/picture.png"}`,
			want: "/account/picture.png",
		},
		{
			name: "UploadAccountProfilePicture",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UploadAccountProfilePicture(ctx, charAccessToken, charPictureBytes, "face.png")
				if err != nil {
					return nil, err
				}
				return got.PictureUrl, nil
			},
			verb: "POST", path: "/api/v1/account/profile-picture", contentTypePrefix: charMultipart,
			bodyHas:       []string{`name="picture"`, `filename="face.png"`, "the-picture-bytes"},
			successStatus: 200, reply: `{"success":true,"pictureUrl":"/account/picture.png"}`,
			want: "/account/picture.png",
		},
		{
			name: "DeleteAccountProfilePicture",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				return nil, c.DeleteAccountProfilePicture(ctx, charAccessToken)
			},
			verb: "DELETE", path: "/api/v1/account/profile-picture",
			successStatus: 200, reply: `{}`,
		},

		// --- audit_log_client.go ----------------------------------------------------------
		{
			name: "GetSettingsAuditLogs",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetSettingsAuditLogs(ctx, charAccessToken)
				if err != nil {
					return nil, err
				}
				return got.AuditLogRetentionDays, nil
			},
			verb: "GET", path: "/api/v1/admin/settings/audit-logs", contentType: charJSON,
			successStatus: 200, reply: `{"auditLogRetentionDays":30}`, want: 30,
		},
		{
			name: "UpdateSettingsAuditLogs",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UpdateSettingsAuditLogs(ctx, charAccessToken, charUpdateAuditSettings)
				if err != nil {
					return nil, err
				}
				return got.AuditLogRetentionDays, nil
			},
			verb: "PUT", path: "/api/v1/admin/settings/audit-logs", contentType: charJSON,
			bodyOf:        charUpdateAuditSettings,
			successStatus: 200, reply: `{"auditLogRetentionDays":30}`, want: 30,
		},
		{
			name: "GetAuditLogsPaginated",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetAuditLogsPaginated(ctx, charAccessToken, 2, 25, "AuditUserLogin", "a request id")
				if err != nil {
					return nil, err
				}
				return got.Total, nil
			},
			verb: "GET", path: "/api/v1/admin/audit-logs",
			query:         "page=2&size=25&auditEvent=AuditUserLogin&requestId=a+request+id",
			contentType:   charJSON,
			successStatus: 200, reply: `{"auditLogs":[],"total":7}`, want: 7,
		},
		{
			name: "GetAuditEventTypes",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetAuditEventTypes(ctx, charAccessToken)
				if err != nil {
					return nil, err
				}
				return got.AuditEventTypes[0], nil
			},
			verb: "GET", path: "/api/v1/admin/audit-logs/event-types", contentType: charJSON,
			successStatus: 200, reply: `{"auditEventTypes":["AuditUserLogin"]}`, want: "AuditUserLogin",
		},

		// --- client_client.go -------------------------------------------------------------
		{
			name: "GetAllClients",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetAllClients(ctx, charAccessToken)
				if err != nil {
					return nil, err
				}
				return got[0].Id, nil
			},
			verb: "GET", path: "/api/v1/admin/clients", contentType: charJSON, anySuccess2xx: true,
			reply: `{"clients":[{"id":3}]}`, want: int64(3),
		},
		{
			name: "GetClientById",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetClientById(ctx, charAccessToken, 3)
				if err != nil {
					return nil, err
				}
				return got.Id, nil
			},
			verb: "GET", path: "/api/v1/admin/clients/3", contentType: charJSON, anySuccess2xx: true,
			reply: `{"client":{"id":3}}`, want: int64(3),
		},
		{
			name: "CreateClient",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.CreateClient(ctx, charAccessToken, charCreateClient)
				if err != nil {
					return nil, err
				}
				return got.Id, nil
			},
			verb: "POST", path: "/api/v1/admin/clients", contentType: charJSON,
			bodyOf: charCreateClient, anySuccess2xx: true,
			reply: `{"client":{"id":4}}`, want: int64(4),
		},
		{
			name: "UpdateClient",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UpdateClient(ctx, charAccessToken, 3, charUpdateClient)
				if err != nil {
					return nil, err
				}
				return got.Id, nil
			},
			verb: "PUT", path: "/api/v1/admin/clients/3", contentType: charJSON,
			bodyOf: charUpdateClient, anySuccess2xx: true,
			reply: `{"client":{"id":3}}`, want: int64(3),
		},
		{
			name: "UpdateClientAuthentication",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UpdateClientAuthentication(ctx, charAccessToken, 3, charUpdateClientAuth)
				if err != nil {
					return nil, err
				}
				return got.Id, nil
			},
			verb: "PUT", path: "/api/v1/admin/clients/3/authentication", contentType: charJSON,
			bodyOf: charUpdateClientAuth, anySuccess2xx: true,
			reply: `{"client":{"id":3}}`, want: int64(3),
		},
		{
			name: "UpdateClientOAuth2Flows",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UpdateClientOAuth2Flows(ctx, charAccessToken, 3, charUpdateClientFlows)
				if err != nil {
					return nil, err
				}
				return got.Id, nil
			},
			verb: "PUT", path: "/api/v1/admin/clients/3/oauth2-flows", contentType: charJSON,
			bodyOf: charUpdateClientFlows, anySuccess2xx: true,
			reply: `{"client":{"id":3}}`, want: int64(3),
		},
		{
			name: "DeleteClient",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				return nil, c.DeleteClient(ctx, charAccessToken, 3)
			},
			verb: "DELETE", path: "/api/v1/admin/clients/3", contentType: charJSON, anySuccess2xx: true,
			reply: `{}`,
		},
		{
			name: "UpdateClientRedirectURIs",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UpdateClientRedirectURIs(ctx, charAccessToken, 3, charUpdateClientRedir)
				if err != nil {
					return nil, err
				}
				return got.Id, nil
			},
			verb: "PUT", path: "/api/v1/admin/clients/3/redirect-uris", contentType: charJSON,
			bodyOf: charUpdateClientRedir, anySuccess2xx: true,
			reply: `{"client":{"id":3}}`, want: int64(3),
		},
		{
			name: "UpdateClientWebOrigins",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UpdateClientWebOrigins(ctx, charAccessToken, 3, charUpdateClientOrig)
				if err != nil {
					return nil, err
				}
				return got.Id, nil
			},
			verb: "PUT", path: "/api/v1/admin/clients/3/web-origins", contentType: charJSON,
			bodyOf: charUpdateClientOrig, anySuccess2xx: true,
			reply: `{"client":{"id":3}}`, want: int64(3),
		},
		{
			name: "UpdateClientTokens",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UpdateClientTokens(ctx, charAccessToken, 3, charUpdateClientToken)
				if err != nil {
					return nil, err
				}
				return got.Id, nil
			},
			verb: "PUT", path: "/api/v1/admin/clients/3/tokens", contentType: charJSON,
			bodyOf: charUpdateClientToken, anySuccess2xx: true,
			reply: `{"client":{"id":3}}`, want: int64(3),
		},
		{
			name: "GetClientLogo",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetClientLogo(ctx, charAccessToken, 3)
				if err != nil {
					return nil, err
				}
				return got.LogoUrl, nil
			},
			verb: "GET", path: "/api/v1/admin/clients/3/logo", contentType: charJSON,
			successStatus: 200, reply: `{"hasLogo":true,"logoUrl":"/clients/3/logo.png"}`,
			want: "/clients/3/logo.png",
		},
		{
			name: "UploadClientLogo",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UploadClientLogo(ctx, charAccessToken, 3, charPictureBytes, "logo.png")
				if err != nil {
					return nil, err
				}
				return got.PictureUrl, nil
			},
			verb: "POST", path: "/api/v1/admin/clients/3/logo", contentTypePrefix: charMultipart,
			bodyHas:       []string{`filename="logo.png"`, "the-picture-bytes"},
			successStatus: 200, reply: `{"success":true,"pictureUrl":"/clients/3/logo.png"}`,
			want: "/clients/3/logo.png",
		},
		{
			name: "DeleteClientLogo",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				return nil, c.DeleteClientLogo(ctx, charAccessToken, 3)
			},
			verb: "DELETE", path: "/api/v1/admin/clients/3/logo",
			successStatus: 200, reply: `{}`,
		},

		// --- client_permission_client.go --------------------------------------------------
		{
			name: "GetClientPermissions",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				client, permissions, err := c.GetClientPermissions(ctx, charAccessToken, 3)
				if err != nil {
					return nil, err
				}
				return []any{client.Id, permissions[0].Id}, nil
			},
			verb: "GET", path: "/api/v1/admin/clients/3/permissions",
			successStatus: 200, reply: `{"client":{"id":3},"permissions":[{"id":8}]}`,
			want: []any{int64(3), int64(8)},
		},
		{
			name: "UpdateClientPermissions",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				return nil, c.UpdateClientPermissions(ctx, charAccessToken, 3, charUpdateClientPerms)
			},
			verb: "PUT", path: "/api/v1/admin/clients/3/permissions", contentType: charJSON,
			bodyOf:        charUpdateClientPerms,
			successStatus: 200, reply: `{}`,
		},

		// --- group_attribute_client.go ----------------------------------------------------
		{
			name: "GetGroupAttributesByGroupId",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetGroupAttributesByGroupId(ctx, charAccessToken, 5)
				if err != nil {
					return nil, err
				}
				return got[0].Id, nil
			},
			verb: "GET", path: "/api/v1/admin/groups/5/attributes", contentType: charJSON,
			successStatus: 200, reply: `{"attributes":[{"id":11}]}`, want: int64(11),
		},
		{
			name: "GetGroupAttributeById",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetGroupAttributeById(ctx, charAccessToken, 11)
				if err != nil {
					return nil, err
				}
				return got.Id, nil
			},
			verb: "GET", path: "/api/v1/admin/group-attributes/11", contentType: charJSON,
			successStatus: 200, reply: `{"attribute":{"id":11}}`, want: int64(11),
		},
		{
			name: "CreateGroupAttribute",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.CreateGroupAttribute(ctx, charAccessToken, charCreateGroupAttr)
				if err != nil {
					return nil, err
				}
				return got.Id, nil
			},
			verb: "POST", path: "/api/v1/admin/group-attributes", contentType: charJSON,
			bodyOf:        charCreateGroupAttr,
			successStatus: 201, reply: `{"attribute":{"id":12}}`, want: int64(12),
		},
		{
			name: "UpdateGroupAttribute",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UpdateGroupAttribute(ctx, charAccessToken, 11, charUpdateGroupAttr)
				if err != nil {
					return nil, err
				}
				return got.Value, nil
			},
			verb: "PUT", path: "/api/v1/admin/group-attributes/11", contentType: charJSON,
			bodyOf:        charUpdateGroupAttr,
			successStatus: 200, reply: `{"attribute":{"value":"support"}}`, want: "support",
		},
		{
			name: "DeleteGroupAttribute",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				return nil, c.DeleteGroupAttribute(ctx, charAccessToken, 11)
			},
			verb: "DELETE", path: "/api/v1/admin/group-attributes/11", contentType: charJSON,
			successStatus: 200, reply: `{}`,
		},

		// --- group_client.go --------------------------------------------------------------
		{
			name: "GetAllGroups",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetAllGroups(ctx, charAccessToken)
				if err != nil {
					return nil, err
				}
				return got[0].Id, nil
			},
			verb: "GET", path: "/api/v1/admin/groups",
			successStatus: 200, reply: `{"groups":[{"id":5}]}`, want: int64(5),
		},
		{
			name: "CreateGroup",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.CreateGroup(ctx, charAccessToken, charCreateGroup)
				if err != nil {
					return nil, err
				}
				return got.Id, nil
			},
			verb: "POST", path: "/api/v1/admin/groups", contentType: charJSON,
			bodyOf:        charCreateGroup,
			successStatus: 201, reply: `{"group":{"id":6}}`, want: int64(6),
		},
		{
			name: "GetGroupById",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetGroupById(ctx, charAccessToken, 5)
				if err != nil {
					return nil, err
				}
				return got.Id, nil
			},
			verb: "GET", path: "/api/v1/admin/groups/5",
			successStatus: 200, reply: `{"group":{"id":5}}`, want: int64(5),
		},
		{
			name: "UpdateGroup",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UpdateGroup(ctx, charAccessToken, 5, charUpdateGroup)
				if err != nil {
					return nil, err
				}
				return got.Id, nil
			},
			verb: "PUT", path: "/api/v1/admin/groups/5", contentType: charJSON,
			bodyOf:        charUpdateGroup,
			successStatus: 200, reply: `{"group":{"id":5}}`, want: int64(5),
		},
		{
			name: "DeleteGroup",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				return nil, c.DeleteGroup(ctx, charAccessToken, 5)
			},
			verb: "DELETE", path: "/api/v1/admin/groups/5",
			successStatus: 200, reply: `{}`,
		},
		{
			name: "GetUserGroups",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				user, groups, err := c.GetUserGroups(ctx, charAccessToken, 42)
				if err != nil {
					return nil, err
				}
				return []any{user.Id, groups[0].Id}, nil
			},
			verb: "GET", path: "/api/v1/admin/users/42/groups",
			successStatus: 200, reply: `{"user":{"id":42},"groups":[{"id":5}]}`,
			want: []any{int64(42), int64(5)},
		},
		{
			name: "GetGroupMembers",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				members, total, err := c.GetGroupMembers(ctx, charAccessToken, 5, 1, 10)
				if err != nil {
					return nil, err
				}
				return []any{members[0].Id, total}, nil
			},
			verb: "GET", path: "/api/v1/admin/groups/5/members", query: "page=1&size=10",
			successStatus: 200, reply: `{"members":[{"id":42}],"total":3}`,
			want: []any{int64(42), 3},
		},
		{
			name: "AddUserToGroup",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				return nil, c.AddUserToGroup(ctx, charAccessToken, 5, 42)
			},
			verb: "POST", path: "/api/v1/admin/groups/5/members", contentType: charJSON,
			body:          `{"userId":42}`,
			successStatus: 201, reply: `{}`,
		},
		{
			name: "RemoveUserFromGroup",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				return nil, c.RemoveUserFromGroup(ctx, charAccessToken, 5, 42)
			},
			verb: "DELETE", path: "/api/v1/admin/groups/5/members/42",
			successStatus: 200, reply: `{}`,
		},
		{
			name: "SearchUsersWithGroupAnnotation",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				users, total, err := c.SearchUsersWithGroupAnnotation(ctx, charAccessToken, "jane doe", 5, 1, 10)
				if err != nil {
					return nil, err
				}
				return []any{users[0].InGroup, total}, nil
			},
			verb: "GET", path: "/api/v1/admin/users/search",
			query:         "query=jane+doe&annotateGroupMembership=5&page=1&size=10",
			successStatus: 200, reply: `{"users":[{"id":42,"inGroup":true}],"total":2}`,
			want: []any{true, 2},
		},
		{
			name: "SearchGroupsWithPermissionAnnotation",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				groups, total, err := c.SearchGroupsWithPermissionAnnotation(ctx, charAccessToken, 8, 1, 10)
				if err != nil {
					return nil, err
				}
				return []any{groups[0].HasPermission, total}, nil
			},
			verb: "GET", path: "/api/v1/admin/groups/search",
			query:         "annotatePermissionId=8&page=1&size=10",
			successStatus: 200, reply: `{"groups":[{"id":5,"hasPermission":true}],"total":1}`,
			want: []any{true, 1},
		},
		{
			name: "UpdateUserGroups",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				user, groups, err := c.UpdateUserGroups(ctx, charAccessToken, 42, charUpdateUserGrps)
				if err != nil {
					return nil, err
				}
				return []any{user.Id, groups[0].Id}, nil
			},
			verb: "PUT", path: "/api/v1/admin/users/42/groups", contentType: charJSON,
			bodyOf:        charUpdateUserGrps,
			successStatus: 200, reply: `{"user":{"id":42},"groups":[{"id":5}]}`,
			want: []any{int64(42), int64(5)},
		},

		// --- group_permission_client.go ---------------------------------------------------
		{
			name: "GetGroupPermissions",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				group, permissions, err := c.GetGroupPermissions(ctx, charAccessToken, 5)
				if err != nil {
					return nil, err
				}
				return []any{group.Id, permissions[0].Id}, nil
			},
			verb: "GET", path: "/api/v1/admin/groups/5/permissions",
			successStatus: 200, reply: `{"group":{"id":5},"permissions":[{"id":8}]}`,
			want: []any{int64(5), int64(8)},
		},
		{
			name: "UpdateGroupPermissions",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				return nil, c.UpdateGroupPermissions(ctx, charAccessToken, 5, charUpdateGroupPerm)
			},
			verb: "PUT", path: "/api/v1/admin/groups/5/permissions", contentType: charJSON,
			bodyOf:        charUpdateGroupPerm,
			successStatus: 200, reply: `{}`,
		},

		// --- permission_client.go ---------------------------------------------------------
		{
			name: "GetUserPermissions",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				user, permissions, err := c.GetUserPermissions(ctx, charAccessToken, 42)
				if err != nil {
					return nil, err
				}
				return []any{user.Id, permissions[0].Id}, nil
			},
			verb: "GET", path: "/api/v1/admin/users/42/permissions", contentType: charJSON,
			successStatus: 200, reply: `{"user":{"id":42},"permissions":[{"id":8}]}`,
			want: []any{int64(42), int64(8)},
		},
		{
			name: "UpdateUserPermissions",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				return nil, c.UpdateUserPermissions(ctx, charAccessToken, 42, charUpdateUserPerm)
			},
			verb: "PUT", path: "/api/v1/admin/users/42/permissions", contentType: charJSON,
			bodyOf:        charUpdateUserPerm,
			successStatus: 200, reply: `{}`,
		},
		{
			name: "GetAllResources",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetAllResources(ctx, charAccessToken)
				if err != nil {
					return nil, err
				}
				return got[0].Id, nil
			},
			verb: "GET", path: "/api/v1/admin/resources", contentType: charJSON,
			successStatus: 200, reply: `{"resources":[{"id":2}]}`, want: int64(2),
		},
		{
			name: "GetPermissionsByResource",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetPermissionsByResource(ctx, charAccessToken, 2)
				if err != nil {
					return nil, err
				}
				return got[0].Id, nil
			},
			verb: "GET", path: "/api/v1/admin/resources/2/permissions", contentType: charJSON,
			successStatus: 200, reply: `{"permissions":[{"id":8}]}`, want: int64(8),
		},
		{
			name: "UpdateResourcePermissions",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				return nil, c.UpdateResourcePermissions(ctx, charAccessToken, 2, charUpdateResPerms)
			},
			verb: "PUT", path: "/api/v1/admin/resources/2/permissions", contentType: charJSON,
			bodyOf:        charUpdateResPerms,
			successStatus: 200, reply: `{}`,
		},
		{
			name: "GetUsersByPermission",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				users, total, err := c.GetUsersByPermission(ctx, charAccessToken, 8, 1, 10)
				if err != nil {
					return nil, err
				}
				return []any{users[0].Id, total}, nil
			},
			verb: "GET", path: "/api/v1/admin/permissions/8/users", query: "page=1&size=10",
			contentType:   charJSON,
			successStatus: 200, reply: `{"users":[{"id":42}],"total":4}`,
			want: []any{int64(42), 4},
		},
		{
			name: "SearchUsersWithPermissionAnnotation",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				users, total, err := c.SearchUsersWithPermissionAnnotation(ctx, charAccessToken, 8, "jane doe", 1, 10)
				if err != nil {
					return nil, err
				}
				return []any{users[0].HasPermission, total}, nil
			},
			verb: "GET", path: "/api/v1/admin/users/search",
			query:         "annotatePermissionId=8&page=1&size=10&query=jane+doe",
			successStatus: 200, reply: `{"users":[{"id":42,"hasPermission":true}],"total":2}`,
			want: []any{true, 2},
		},

		// --- phone_client.go --------------------------------------------------------------
		{
			name: "UpdateUserPhone",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UpdateUserPhone(ctx, charAccessToken, 42, charUpdateUserPhone)
				if err != nil {
					return nil, err
				}
				return got.PhoneNumber, nil
			},
			verb: "PUT", path: "/api/v1/admin/users/42/phone", contentType: charJSON,
			bodyOf:        charUpdateUserPhone,
			successStatus: 200, reply: `{"user":{"phoneNumber":"5555678"}}`, want: "5555678",
		},
		{
			name: "GetPhoneCountries",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetPhoneCountries(ctx, charAccessToken)
				if err != nil {
					return nil, err
				}
				return got[0].UniqueId, nil
			},
			verb: "GET", path: "/api/v1/admin/phone-countries", contentType: charJSON,
			successStatus: 200, reply: `{"phoneCountries":[{"uniqueId":"BRA_0"}]}`, want: "BRA_0",
		},

		// --- resource_client.go -----------------------------------------------------------
		{
			name: "CreateResource",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.CreateResource(ctx, charAccessToken, charCreateResource)
				if err != nil {
					return nil, err
				}
				return got.Id, nil
			},
			verb: "POST", path: "/api/v1/admin/resources", contentType: charJSON,
			bodyOf:        charCreateResource,
			successStatus: 201, reply: `{"resource":{"id":2}}`, want: int64(2),
		},
		{
			name: "GetResourceById",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetResourceById(ctx, charAccessToken, 2)
				if err != nil {
					return nil, err
				}
				return got.Id, nil
			},
			verb: "GET", path: "/api/v1/admin/resources/2", contentType: charJSON,
			successStatus: 200, reply: `{"resource":{"id":2}}`, want: int64(2),
		},
		{
			name: "UpdateResource",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UpdateResource(ctx, charAccessToken, 2, charUpdateResource)
				if err != nil {
					return nil, err
				}
				return got.ResourceIdentifier, nil
			},
			verb: "PUT", path: "/api/v1/admin/resources/2", contentType: charJSON,
			bodyOf:        charUpdateResource,
			successStatus: 200, reply: `{"resource":{"resourceIdentifier":"a-resource"}}`, want: "a-resource",
		},
		{
			name: "DeleteResource",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				return nil, c.DeleteResource(ctx, charAccessToken, 2)
			},
			verb: "DELETE", path: "/api/v1/admin/resources/2", contentType: charJSON,
			successStatus: 200, reply: `{}`,
		},

		// --- settings_email_client.go -----------------------------------------------------
		{
			name: "GetSettingsEmail",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetSettingsEmail(ctx, charAccessToken)
				if err != nil {
					return nil, err
				}
				return got.SMTPHost, nil
			},
			verb: "GET", path: "/api/v1/admin/settings/email", contentType: charJSON,
			successStatus: 200, reply: `{"smtpHost":"smtp.example.com"}`, want: "smtp.example.com",
		},
		{
			name: "UpdateSettingsEmail",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UpdateSettingsEmail(ctx, charAccessToken, charUpdateEmailSettings)
				if err != nil {
					return nil, err
				}
				return got.SMTPHost, nil
			},
			verb: "PUT", path: "/api/v1/admin/settings/email", contentType: charJSON,
			bodyOf:        charUpdateEmailSettings,
			successStatus: 200, reply: `{"smtpHost":"smtp.example.com"}`, want: "smtp.example.com",
		},
		{
			name: "SendTestEmail",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				return nil, c.SendTestEmail(ctx, charAccessToken, charSendTestEmail)
			},
			verb: "POST", path: "/api/v1/admin/settings/email/send-test", contentType: charJSON,
			bodyOf:        charSendTestEmail,
			successStatus: 200, reply: `{}`,
		},

		// --- settings_general_client.go ---------------------------------------------------
		{
			name: "GetSettingsGeneral",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetSettingsGeneral(ctx, charAccessToken)
				if err != nil {
					return nil, err
				}
				return got.AppName, nil
			},
			verb: "GET", path: "/api/v1/admin/settings/general", contentType: charJSON,
			successStatus: 200, reply: `{"appName":"Goiabada"}`, want: "Goiabada",
		},
		{
			name: "UpdateSettingsGeneral",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UpdateSettingsGeneral(ctx, charAccessToken, charUpdateGeneralSettings)
				if err != nil {
					return nil, err
				}
				return got.AppName, nil
			},
			verb: "PUT", path: "/api/v1/admin/settings/general", contentType: charJSON,
			bodyOf:        charUpdateGeneralSettings,
			successStatus: 200, reply: `{"appName":"Goiabada"}`, want: "Goiabada",
		},

		// --- settings_keys_client.go ------------------------------------------------------
		{
			name: "GetSettingsKeys",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetSettingsKeys(ctx, charAccessToken)
				if err != nil {
					return nil, err
				}
				return got[0].KeyIdentifier, nil
			},
			verb: "GET", path: "/api/v1/admin/settings/keys",
			successStatus: 200, reply: `{"keys":[{"id":1,"keyIdentifier":"a-key-id"}]}`,
			want: "a-key-id", readErrorIsNotAnError: true,
		},
		{
			name: "RotateSettingsKeys",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				return nil, c.RotateSettingsKeys(ctx, charAccessToken)
			},
			verb: "POST", path: "/api/v1/admin/settings/keys/rotate", contentType: charJSON,
			body:          `{}`,
			successStatus: 200, reply: `{}`, readErrorIsNotAnError: true,
		},
		{
			name: "DeleteSettingsKey",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				return nil, c.DeleteSettingsKey(ctx, charAccessToken, 7)
			},
			verb: "DELETE", path: "/api/v1/admin/settings/keys/7",
			successStatus: 200, reply: `{}`, readErrorIsNotAnError: true,
		},

		// --- settings_sessions_client.go --------------------------------------------------
		{
			name: "GetSettingsSessions",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetSettingsSessions(ctx, charAccessToken)
				if err != nil {
					return nil, err
				}
				return got.UserSessionIdleTimeoutInSeconds, nil
			},
			verb: "GET", path: "/api/v1/admin/settings/sessions", contentType: charJSON,
			successStatus: 200, reply: `{"userSessionIdleTimeoutInSeconds":900}`, want: 900,
		},
		{
			name: "UpdateSettingsSessions",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UpdateSettingsSessions(ctx, charAccessToken, charUpdateSessionsSettings)
				if err != nil {
					return nil, err
				}
				return got.UserSessionIdleTimeoutInSeconds, nil
			},
			verb: "PUT", path: "/api/v1/admin/settings/sessions", contentType: charJSON,
			bodyOf:        charUpdateSessionsSettings,
			successStatus: 200, reply: `{"userSessionIdleTimeoutInSeconds":900}`, want: 900,
		},

		// --- settings_tokens_client.go ----------------------------------------------------
		{
			name: "GetSettingsTokens",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetSettingsTokens(ctx, charAccessToken)
				if err != nil {
					return nil, err
				}
				return got.TokenExpirationInSeconds, nil
			},
			verb: "GET", path: "/api/v1/admin/settings/tokens", contentType: charJSON,
			successStatus: 200, reply: `{"tokenExpirationInSeconds":300}`, want: 300,
		},
		{
			name: "UpdateSettingsTokens",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UpdateSettingsTokens(ctx, charAccessToken, charUpdateTokensSettings)
				if err != nil {
					return nil, err
				}
				return got.TokenExpirationInSeconds, nil
			},
			verb: "PUT", path: "/api/v1/admin/settings/tokens", contentType: charJSON,
			bodyOf:        charUpdateTokensSettings,
			successStatus: 200, reply: `{"tokenExpirationInSeconds":300}`, want: 300,
		},

		// --- settings_ui_theme_client.go --------------------------------------------------
		{
			name: "GetSettingsUITheme",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetSettingsUITheme(ctx, charAccessToken)
				if err != nil {
					return nil, err
				}
				return got.UITheme, nil
			},
			verb: "GET", path: "/api/v1/admin/settings/ui-theme", contentType: charJSON,
			successStatus: 200, reply: `{"uiTheme":"dark"}`, want: "dark",
		},
		{
			name: "UpdateSettingsUITheme",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UpdateSettingsUITheme(ctx, charAccessToken, charUpdateUIThemeSettings)
				if err != nil {
					return nil, err
				}
				return got.UITheme, nil
			},
			verb: "PUT", path: "/api/v1/admin/settings/ui-theme", contentType: charJSON,
			bodyOf:        charUpdateUIThemeSettings,
			successStatus: 200, reply: `{"uiTheme":"dark"}`, want: "dark",
		},

		// --- user_attribute_client.go -----------------------------------------------------
		{
			name: "GetUserAttributesByUserId",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetUserAttributesByUserId(ctx, charAccessToken, 42)
				if err != nil {
					return nil, err
				}
				return got[0].Id, nil
			},
			verb: "GET", path: "/api/v1/admin/users/42/attributes", contentType: charJSON,
			successStatus: 200, reply: `{"attributes":[{"id":21}]}`, want: int64(21),
		},
		{
			name: "GetUserAttributeById",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetUserAttributeById(ctx, charAccessToken, 21)
				if err != nil {
					return nil, err
				}
				return got.Id, nil
			},
			verb: "GET", path: "/api/v1/admin/user-attributes/21", contentType: charJSON,
			successStatus: 200, reply: `{"attribute":{"id":21}}`, want: int64(21),
		},
		{
			name: "CreateUserAttribute",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.CreateUserAttribute(ctx, charAccessToken, charCreateUserAttr)
				if err != nil {
					return nil, err
				}
				return got.Id, nil
			},
			verb: "POST", path: "/api/v1/admin/user-attributes", contentType: charJSON,
			bodyOf:        charCreateUserAttr,
			successStatus: 201, reply: `{"attribute":{"id":22}}`, want: int64(22),
		},
		{
			name: "UpdateUserAttribute",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UpdateUserAttribute(ctx, charAccessToken, 21, charUpdateUserAttr)
				if err != nil {
					return nil, err
				}
				return got.Value, nil
			},
			verb: "PUT", path: "/api/v1/admin/user-attributes/21", contentType: charJSON,
			bodyOf:        charUpdateUserAttr,
			successStatus: 200, reply: `{"attribute":{"value":"blue"}}`, want: "blue",
		},
		{
			name: "DeleteUserAttribute",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				return nil, c.DeleteUserAttribute(ctx, charAccessToken, 21)
			},
			verb: "DELETE", path: "/api/v1/admin/user-attributes/21", contentType: charJSON,
			successStatus: 200, reply: `{}`,
		},

		// --- user_client.go ---------------------------------------------------------------
		{
			name: "SearchUsersPaginated",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				users, total, err := c.SearchUsersPaginated(ctx, charAccessToken, "jane doe", 1, 10)
				if err != nil {
					return nil, err
				}
				return []any{users[0].Id, total}, nil
			},
			verb: "GET", path: "/api/v1/admin/users/search", query: "page=1&query=jane+doe&size=10",
			contentType:   charJSON,
			successStatus: 200, reply: `{"users":[{"id":42}],"total":5}`,
			want: []any{int64(42), 5},
		},
		{
			name: "GetUserById",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetUserById(ctx, charAccessToken, 42)
				if err != nil {
					return nil, err
				}
				return got.Id, nil
			},
			verb: "GET", path: "/api/v1/admin/users/42", contentType: charJSON,
			successStatus: 200, reply: `{"user":{"id":42}}`, want: int64(42),
		},
		{
			name: "UpdateUserEnabled",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UpdateUserEnabled(ctx, charAccessToken, 42, true)
				if err != nil {
					return nil, err
				}
				return got.Enabled, nil
			},
			verb: "PUT", path: "/api/v1/admin/users/42/enabled", contentType: charJSON,
			body:          `{"enabled":true}`,
			successStatus: 200, reply: `{"user":{"enabled":true}}`, want: true,
		},
		{
			name: "UpdateUserProfile",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UpdateUserProfile(ctx, charAccessToken, 42, charUpdateUserProfile)
				if err != nil {
					return nil, err
				}
				return got.Username, nil
			},
			verb: "PUT", path: "/api/v1/admin/users/42/profile", contentType: charJSON,
			bodyOf:        charUpdateUserProfile,
			successStatus: 200, reply: `{"user":{"username":"jdoe"}}`, want: "jdoe",
		},
		{
			name: "UpdateUserAddress",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UpdateUserAddress(ctx, charAccessToken, 42, charUpdateUserAddress)
				if err != nil {
					return nil, err
				}
				return got.AddressLine1, nil
			},
			verb: "PUT", path: "/api/v1/admin/users/42/address", contentType: charJSON,
			bodyOf:        charUpdateUserAddress,
			successStatus: 200, reply: `{"user":{"addressLine1":"1 Main Street"}}`, want: "1 Main Street",
		},
		{
			name: "UpdateUserEmail",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UpdateUserEmail(ctx, charAccessToken, 42, charUpdateUserMail)
				if err != nil {
					return nil, err
				}
				return got.Email, nil
			},
			verb: "PUT", path: "/api/v1/admin/users/42/email", contentType: charJSON,
			bodyOf:        charUpdateUserMail,
			successStatus: 200, reply: `{"user":{"email":"jane@example.com"}}`, want: "jane@example.com",
		},
		{
			name: "UpdateUserPassword",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UpdateUserPassword(ctx, charAccessToken, 42, charUpdateUserPwd)
				if err != nil {
					return nil, err
				}
				return got.Id, nil
			},
			verb: "PUT", path: "/api/v1/admin/users/42/password", contentType: charJSON,
			bodyOf:        charUpdateUserPwd,
			successStatus: 200, reply: `{"user":{"id":42}}`, want: int64(42),
		},
		{
			name: "UpdateUserOTP",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UpdateUserOTP(ctx, charAccessToken, 42, charUpdateUserOTP)
				if err != nil {
					return nil, err
				}
				return got.OTPEnabled, nil
			},
			verb: "PUT", path: "/api/v1/admin/users/42/otp", contentType: charJSON,
			bodyOf:        charUpdateUserOTP,
			successStatus: 200, reply: `{"user":{"otpEnabled":false}}`, want: false,
		},
		{
			name: "CreateUserAdmin",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.CreateUserAdmin(ctx, charAccessToken, charCreateUser)
				if err != nil {
					return nil, err
				}
				return got.Id, nil
			},
			verb: "POST", path: "/api/v1/admin/users/create", contentType: charJSON,
			bodyOf:        charCreateUser,
			successStatus: 201, reply: `{"user":{"id":99}}`, want: int64(99),
		},
		{
			name: "GetUserProfilePicture",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetUserProfilePicture(ctx, charAccessToken, 42)
				if err != nil {
					return nil, err
				}
				return got.PictureUrl, nil
			},
			verb: "GET", path: "/api/v1/admin/users/42/profile-picture", contentType: charJSON,
			successStatus: 200, reply: `{"hasPicture":true,"pictureUrl":"/users/42/picture.png"}`,
			want: "/users/42/picture.png",
		},
		{
			name: "UploadUserProfilePicture",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.UploadUserProfilePicture(ctx, charAccessToken, 42, charPictureBytes, "face.png")
				if err != nil {
					return nil, err
				}
				return got.PictureUrl, nil
			},
			verb: "POST", path: "/api/v1/admin/users/42/profile-picture", contentTypePrefix: charMultipart,
			bodyHas:       []string{`filename="face.png"`, "the-picture-bytes"},
			successStatus: 200, reply: `{"success":true,"pictureUrl":"/users/42/picture.png"}`,
			want: "/users/42/picture.png",
		},
		{
			name: "DeleteUserProfilePicture",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				return nil, c.DeleteUserProfilePicture(ctx, charAccessToken, 42)
			},
			verb: "DELETE", path: "/api/v1/admin/users/42/profile-picture",
			successStatus: 200, reply: `{}`,
		},
		{
			name: "DeleteUser",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				return nil, c.DeleteUser(ctx, charAccessToken, 42)
			},
			verb: "DELETE", path: "/api/v1/admin/users/42", contentType: charJSON,
			successStatus: 200, reply: `{}`,
		},

		// --- user_session_client.go -------------------------------------------------------
		{
			name: "GetUserSessionsByUserId",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetUserSessionsByUserId(ctx, charAccessToken, 42)
				if err != nil {
					return nil, err
				}
				return got[0].IsCurrent, nil
			},
			verb: "GET", path: "/api/v1/admin/users/42/sessions", contentType: charJSON,
			successStatus: 200, reply: `{"sessions":[{"isCurrent":true}]}`, want: true,
		},
		{
			name: "DeleteUserSessionById",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				return nil, c.DeleteUserSessionById(ctx, charAccessToken, 31)
			},
			verb: "DELETE", path: "/api/v1/admin/user-sessions/31", contentType: charJSON,
			successStatus: 200, reply: `{"success":true}`,
		},
		{
			name: "GetClientSessionsByClientId",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetClientSessionsByClientId(ctx, charAccessToken, 3, 1, 10)
				if err != nil {
					return nil, err
				}
				return got.Sessions[0].IsCurrent, nil
			},
			verb: "GET", path: "/api/v1/admin/clients/3/sessions", query: "page=1&size=10",
			contentType:   charJSON,
			successStatus: 200, reply: `{"sessions":[{"isCurrent":true}],"users":[]}`, want: true,
		},
		{
			name: "GetAccountSessions",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetAccountSessions(ctx, charAccessToken)
				if err != nil {
					return nil, err
				}
				return got[0].IsCurrent, nil
			},
			verb: "GET", path: "/api/v1/account/sessions", contentType: charJSON,
			successStatus: 200, reply: `{"sessions":[{"isCurrent":true}]}`, want: true,
		},
		{
			name: "DeleteAccountSession",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				return nil, c.DeleteAccountSession(ctx, charAccessToken, 31)
			},
			verb: "DELETE", path: "/api/v1/account/sessions/31", contentType: charJSON,
			successStatus: 200, reply: `{"success":true}`,
		},
		{
			name: "GetUserConsents",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				got, err := c.GetUserConsents(ctx, charAccessToken, 42)
				if err != nil {
					return nil, err
				}
				return got[0].Scope, nil
			},
			verb: "GET", path: "/api/v1/admin/users/42/consents", contentType: charJSON,
			successStatus: 200, reply: `{"consents":[{"scope":"openid profile"}]}`, want: "openid profile",
		},
		{
			name: "DeleteUserConsent",
			call: func(ctx context.Context, c *AuthServerClient) (any, error) {
				return nil, c.DeleteUserConsent(ctx, charAccessToken, 13)
			},
			verb: "DELETE", path: "/api/v1/admin/user-consents/13", contentType: charJSON,
			successStatus: 200, reply: `{}`,
		},
	}
}
