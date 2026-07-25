package datatests

import (
	"database/sql"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Cascade deletion.
//
// DeleteUser and DeleteClient are each a single DELETE against the parent table
// (commondb/user.go, commondb/client.go). They remove no child rows themselves,
// so the correctness of "delete a user" lives almost entirely in the ON DELETE
// CASCADE clauses of four separately hand-written schemas. Nothing compared those
// four until these tests, which run against whichever engine is configured.
//
// The per-table checks use assert rather than require deliberately: one run
// should report every table that failed to cascade, not stop at the first.

// createROPCRefreshToken builds a refresh token shaped like one issued by the
// ROPC grant: user_id and client_id set, code_id NULL. See
// TokenIssuer.generateRefreshTokenForROPC, whose comment reads "no Code
// reference". This shape is the reason these tests exist: the auth-code flow
// instead sets only code_id, so those rows are swept up by the codes cascade and
// never exercise the users/clients foreign keys directly.
func createROPCRefreshToken(t *testing.T, userId, clientId int64) *models.RefreshToken {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	refreshToken := &models.RefreshToken{
		UserId:            sql.NullInt64{Int64: userId, Valid: true},
		ClientId:          sql.NullInt64{Int64: clientId, Valid: true},
		RefreshTokenJti:   gofakeit.UUID(),
		SessionIdentifier: gofakeit.UUID(),
		RefreshTokenType:  "Offline",
		Scope:             "openid profile offline_access",
		IssuedAt:          sql.NullTime{Time: now, Valid: true},
		ExpiresAt:         sql.NullTime{Time: now.Add(time.Hour), Valid: true},
		MaxLifetime:       sql.NullTime{Time: now.Add(24 * time.Hour), Valid: true},
		Revoked:           false,
	}
	require.NoError(t, database.CreateRefreshToken(nil, refreshToken), "CreateRefreshToken")
	require.False(t, refreshToken.CodeId.Valid, "code_id must stay NULL for a ROPC-shaped token")
	return refreshToken
}

// createCodeLinkedRefreshToken mirrors the auth-code flow: code_id set, user_id
// and client_id left NULL.
func createCodeLinkedRefreshToken(t *testing.T, codeId int64) *models.RefreshToken {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	refreshToken := &models.RefreshToken{
		CodeId:            sql.NullInt64{Int64: codeId, Valid: true},
		RefreshTokenJti:   gofakeit.UUID(),
		SessionIdentifier: gofakeit.UUID(),
		RefreshTokenType:  "Bearer",
		Scope:             "openid profile",
		IssuedAt:          sql.NullTime{Time: now, Valid: true},
		ExpiresAt:         sql.NullTime{Time: now.Add(time.Hour), Valid: true},
		MaxLifetime:       sql.NullTime{Time: now.Add(24 * time.Hour), Valid: true},
		Revoked:           false,
	}
	require.NoError(t, database.CreateRefreshToken(nil, refreshToken), "CreateRefreshToken")
	return refreshToken
}

func refreshTokenExists(t *testing.T, id int64) bool {
	t.Helper()
	refreshToken, err := database.GetRefreshTokenById(nil, id)
	require.NoError(t, err, "GetRefreshTokenById")
	return refreshToken != nil
}

// =============================================================================
// Minimal repros
//
// A ROPC-issued refresh token must not block deletion of the user or client it
// points at. These are the smallest cases that isolate the users/clients foreign
// keys on refresh_tokens, so a failure here names the cause directly.
// =============================================================================

func TestDeleteUser_ROPCRefreshTokenDoesNotBlockDeletion(t *testing.T) {
	user := createTestUser(t)
	client := createTestClient(t)
	refreshToken := createROPCRefreshToken(t, user.Id, client.Id)

	require.NoError(t, database.DeleteUser(nil, user.Id), "DeleteUser with a ROPC-issued refresh token")

	deletedUser, err := database.GetUserById(nil, user.Id)
	require.NoError(t, err, "GetUserById")
	assert.Nil(t, deletedUser, "user must be gone")
	assert.False(t, refreshTokenExists(t, refreshToken.Id),
		"the ROPC refresh token must be removed with its user")
}

func TestDeleteClient_ROPCRefreshTokenDoesNotBlockDeletion(t *testing.T) {
	user := createTestUser(t)
	client := createTestClient(t)
	refreshToken := createROPCRefreshToken(t, user.Id, client.Id)

	require.NoError(t, database.DeleteClient(nil, client.Id), "DeleteClient with a ROPC-issued refresh token")

	deletedClient, err := database.GetClientById(nil, client.Id)
	require.NoError(t, err, "GetClientById")
	assert.Nil(t, deletedClient, "client must be gone")
	assert.False(t, refreshTokenExists(t, refreshToken.Id),
		"the ROPC refresh token must be removed with its client")
}

// =============================================================================
// Exhaustive: every table with a foreign key to the parent
// =============================================================================

// TestDeleteUser_RemovesAllDependentRows covers all eight tables that reference
// users(id), plus the two second-hop tables that hang off them
// (user_session_clients under user_sessions, refresh_tokens under codes).
func TestDeleteUser_RemovesAllDependentRows(t *testing.T) {
	user := createTestUser(t)
	client := createTestClient(t)

	// Direct children of users.
	code := createTestCode(t, client.Id, user.Id)
	ropcToken := createROPCRefreshToken(t, user.Id, client.Id)
	attribute := createTestUserAttribute(t, user.Id)
	consent := createTestUserConsentForUser(t, user.Id)
	session := createTestUserSessionWithClient(t, user.Id, client.Id)
	group := createTestGroup(t)
	userGroup := createTestUserGroupWithUserAndGroup(t, user.Id, group.Id)
	resource := createTestResource(t)
	permission := createTestPermission(t, resource)
	userPermission := createTestUserPermissionWithUserAndPermission(t, user.Id, permission.Id)
	profilePicture := createTestUserProfilePicture(t, user.Id)

	// Second hop: a refresh token under the code, and the session's client row.
	codeLinkedToken := createCodeLinkedRefreshToken(t, code.Id)
	sessionClients, err := database.GetUserSessionClientsByUserSessionId(nil, session.Id)
	require.NoError(t, err, "GetUserSessionClientsByUserSessionId")
	require.Len(t, sessionClients, 1, "expected the session to have one client row")
	sessionClientId := sessionClients[0].Id

	require.NoError(t, database.DeleteUser(nil, user.Id), "DeleteUser")

	deletedUser, err := database.GetUserById(nil, user.Id)
	require.NoError(t, err, "GetUserById")
	require.Nil(t, deletedUser, "user must be gone")

	// codes
	deletedCode, err := database.GetCodeById(nil, code.Id)
	assert.NoError(t, err, "GetCodeById")
	assert.Nil(t, deletedCode, "codes must cascade from users")

	// refresh_tokens, both shapes
	assert.False(t, refreshTokenExists(t, ropcToken.Id),
		"refresh_tokens must cascade from users (ROPC-shaped, code_id NULL)")
	assert.False(t, refreshTokenExists(t, codeLinkedToken.Id),
		"refresh_tokens must cascade from codes (auth-code-shaped)")

	// user_attributes
	deletedAttribute, err := database.GetUserAttributeById(nil, attribute.Id)
	assert.NoError(t, err, "GetUserAttributeById")
	assert.Nil(t, deletedAttribute, "user_attributes must cascade from users")

	// user_consents
	deletedConsent, err := database.GetUserConsentById(nil, consent.Id)
	assert.NoError(t, err, "GetUserConsentById")
	assert.Nil(t, deletedConsent, "user_consents must cascade from users")

	// user_sessions
	deletedSession, err := database.GetUserSessionById(nil, session.Id)
	assert.NoError(t, err, "GetUserSessionById")
	assert.Nil(t, deletedSession, "user_sessions must cascade from users")

	// user_session_clients (second hop, under user_sessions)
	deletedSessionClient, err := database.GetUserSessionClientById(nil, sessionClientId)
	assert.NoError(t, err, "GetUserSessionClientById")
	assert.Nil(t, deletedSessionClient, "user_session_clients must cascade from user_sessions")

	// users_groups
	deletedUserGroup, err := database.GetUserGroupById(nil, userGroup.Id)
	assert.NoError(t, err, "GetUserGroupById")
	assert.Nil(t, deletedUserGroup, "users_groups must cascade from users")

	// users_permissions
	deletedUserPermission, err := database.GetUserPermissionById(nil, userPermission.Id)
	assert.NoError(t, err, "GetUserPermissionById")
	assert.Nil(t, deletedUserPermission, "users_permissions must cascade from users")

	// user_profile_pictures
	deletedPicture, err := database.GetUserProfilePictureByUserId(nil, user.Id)
	assert.NoError(t, err, "GetUserProfilePictureByUserId")
	assert.Nil(t, deletedPicture, "user_profile_pictures must cascade from users")
	assert.NotZero(t, profilePicture.Id, "sanity: the fixture was created")

	// The group, resource and permission are independent of the user and must
	// survive: cascade must not travel up an association table.
	survivingGroup, err := database.GetGroupById(nil, group.Id)
	assert.NoError(t, err, "GetGroupById")
	assert.NotNil(t, survivingGroup, "deleting a user must not delete the group")
	survivingPermission, err := database.GetPermissionById(nil, permission.Id)
	assert.NoError(t, err, "GetPermissionById")
	assert.NotNil(t, survivingPermission, "deleting a user must not delete the permission")
	survivingClient, err := database.GetClientById(nil, client.Id)
	assert.NoError(t, err, "GetClientById")
	assert.NotNil(t, survivingClient, "deleting a user must not delete the client")
}

// TestDeleteClient_RemovesAllDependentRows covers all eight tables that
// reference clients(id).
func TestDeleteClient_RemovesAllDependentRows(t *testing.T) {
	user := createTestUser(t)
	client := createTestClient(t)

	code := createTestCode(t, client.Id, user.Id)
	ropcToken := createROPCRefreshToken(t, user.Id, client.Id)
	redirectURI := createTestRedirectURI(t, client.Id)
	webOrigin := createTestWebOrigin(t, client.Id)
	logo := createTestClientLogo(t, client.Id)

	resource := createTestResource(t)
	permission := createTestPermission(t, resource)
	clientPermission := &models.ClientPermission{
		ClientId:     client.Id,
		PermissionId: permission.Id,
	}
	require.NoError(t, database.CreateClientPermission(nil, clientPermission), "CreateClientPermission")

	consent := &models.UserConsent{
		UserId:   user.Id,
		ClientId: client.Id,
		Scope:    "openid profile",
	}
	require.NoError(t, database.CreateUserConsent(nil, consent), "CreateUserConsent")

	session := createTestUserSessionWithClient(t, user.Id, client.Id)
	sessionClients, err := database.GetUserSessionClientsByUserSessionId(nil, session.Id)
	require.NoError(t, err, "GetUserSessionClientsByUserSessionId")
	require.Len(t, sessionClients, 1, "expected the session to have one client row")
	sessionClientId := sessionClients[0].Id

	require.NoError(t, database.DeleteClient(nil, client.Id), "DeleteClient")

	deletedClient, err := database.GetClientById(nil, client.Id)
	require.NoError(t, err, "GetClientById")
	require.Nil(t, deletedClient, "client must be gone")

	// codes
	deletedCode, err := database.GetCodeById(nil, code.Id)
	assert.NoError(t, err, "GetCodeById")
	assert.Nil(t, deletedCode, "codes must cascade from clients")

	// refresh_tokens
	assert.False(t, refreshTokenExists(t, ropcToken.Id),
		"refresh_tokens must cascade from clients (ROPC-shaped, code_id NULL)")

	// redirect_uris
	deletedRedirectURI, err := database.GetRedirectURIById(nil, redirectURI.Id)
	assert.NoError(t, err, "GetRedirectURIById")
	assert.Nil(t, deletedRedirectURI, "redirect_uris must cascade from clients")

	// web_origins
	deletedWebOrigin, err := database.GetWebOriginById(nil, webOrigin.Id)
	assert.NoError(t, err, "GetWebOriginById")
	assert.Nil(t, deletedWebOrigin, "web_origins must cascade from clients")

	// client_logos
	deletedLogo, err := database.GetClientLogoByClientId(nil, client.Id)
	assert.NoError(t, err, "GetClientLogoByClientId")
	assert.Nil(t, deletedLogo, "client_logos must cascade from clients")
	assert.NotZero(t, logo.Id, "sanity: the fixture was created")

	// clients_permissions
	deletedClientPermission, err := database.GetClientPermissionById(nil, clientPermission.Id)
	assert.NoError(t, err, "GetClientPermissionById")
	assert.Nil(t, deletedClientPermission, "clients_permissions must cascade from clients")

	// user_consents
	deletedConsent, err := database.GetUserConsentById(nil, consent.Id)
	assert.NoError(t, err, "GetUserConsentById")
	assert.Nil(t, deletedConsent, "user_consents must cascade from clients")

	// user_session_clients
	deletedSessionClient, err := database.GetUserSessionClientById(nil, sessionClientId)
	assert.NoError(t, err, "GetUserSessionClientById")
	assert.Nil(t, deletedSessionClient, "user_session_clients must cascade from clients")

	// The user, its session and the permission are independent of the client.
	survivingUser, err := database.GetUserById(nil, user.Id)
	assert.NoError(t, err, "GetUserById")
	assert.NotNil(t, survivingUser, "deleting a client must not delete the user")
	survivingSession, err := database.GetUserSessionById(nil, session.Id)
	assert.NoError(t, err, "GetUserSessionById")
	assert.NotNil(t, survivingSession, "deleting a client must not delete the user session")
	survivingPermission, err := database.GetPermissionById(nil, permission.Id)
	assert.NoError(t, err, "GetPermissionById")
	assert.NotNil(t, survivingPermission, "deleting a client must not delete the permission")
}
