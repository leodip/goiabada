package datatests

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Cascade deletion.
//
// DeleteUser deletes the user's sessions and refresh tokens first, then the user's
// row; DeleteClient deletes the client's refresh tokens first, then the client's
// row, and records the deleted identifier (commondb/user.go, commondb/client.go).
// Every other child row goes with the parent through the ON DELETE CASCADE
// clauses of four separately hand-written schemas, so the correctness of "delete
// a user" lives mostly there. Nothing compared those four until these tests,
// which run against whichever engine is configured.
//
// The per-table checks use assert rather than require deliberately: one run
// should report every table that failed to cascade, not stop at the first.

// createROPCRefreshToken builds a refresh token shaped like one issued by the
// ROPC grant: user_id and client_id set, code_id NULL. See
// TokenIssuer.generateRefreshTokenForROPC, whose comment reads "no Code
// reference". This shape is the reason these tests exist: the auth-code flow
// instead sets only code_id, so those rows are swept up by the codes cascade and
// never exercise the users/clients foreign keys directly.
func createROPCRefreshToken(t *testing.T, userID, clientID int64) *record.RefreshToken {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	refreshToken := &record.RefreshToken{
		UserID:            sql.NullInt64{Int64: userID, Valid: true},
		ClientID:          sql.NullInt64{Int64: clientID, Valid: true},
		RefreshTokenJTI:   fake.UUID(),
		SessionIdentifier: fake.UUID(),
		RefreshTokenType:  "Offline",
		Scope:             "openid profile offline_access",
		IssuedAt:          sql.NullTime{Time: now, Valid: true},
		ExpiresAt:         sql.NullTime{Time: now.Add(time.Hour), Valid: true},
		MaxLifetime:       sql.NullTime{Time: now.Add(24 * time.Hour), Valid: true},
		Revoked:           false,
	}
	require.NoError(t, database.CreateRefreshToken(context.Background(), nil, refreshToken), "CreateRefreshToken")
	require.False(t, refreshToken.CodeID.Valid, "code_id must stay NULL for a ROPC-shaped token")
	return refreshToken
}

// createCodeLinkedRefreshToken mirrors the auth-code flow: code_id set, user_id
// and client_id left NULL.
func createCodeLinkedRefreshToken(t *testing.T, codeID int64) *record.RefreshToken {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	refreshToken := &record.RefreshToken{
		CodeID:            sql.NullInt64{Int64: codeID, Valid: true},
		RefreshTokenJTI:   fake.UUID(),
		SessionIdentifier: fake.UUID(),
		RefreshTokenType:  "Bearer",
		Scope:             "openid profile",
		IssuedAt:          sql.NullTime{Time: now, Valid: true},
		ExpiresAt:         sql.NullTime{Time: now.Add(time.Hour), Valid: true},
		MaxLifetime:       sql.NullTime{Time: now.Add(24 * time.Hour), Valid: true},
		Revoked:           false,
	}
	require.NoError(t, database.CreateRefreshToken(context.Background(), nil, refreshToken), "CreateRefreshToken")
	return refreshToken
}

func refreshTokenExists(t *testing.T, id int64) bool {
	t.Helper()
	refreshToken, err := database.GetRefreshTokenByID(context.Background(), nil, id)
	require.NoError(t, err, "GetRefreshTokenByID")
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
	refreshToken := createROPCRefreshToken(t, user.ID, client.ID)

	require.NoError(t, database.DeleteUser(context.Background(), nil, user.ID), "DeleteUser with a ROPC-issued refresh token")

	deletedUser, err := database.GetUserByID(context.Background(), nil, user.ID)
	require.NoError(t, err, "GetUserByID")
	assert.Nil(t, deletedUser, "user must be gone")
	assert.False(t, refreshTokenExists(t, refreshToken.ID),
		"the ROPC refresh token must be removed with its user")
}

func TestDeleteClient_ROPCRefreshTokenDoesNotBlockDeletion(t *testing.T) {
	user := createTestUser(t)
	client := createTestClient(t)
	refreshToken := createROPCRefreshToken(t, user.ID, client.ID)

	require.NoError(t, database.DeleteClient(context.Background(), nil, client.ID), "DeleteClient with a ROPC-issued refresh token")

	deletedClient, err := database.GetClientByID(context.Background(), nil, client.ID)
	require.NoError(t, err, "GetClientByID")
	assert.Nil(t, deletedClient, "client must be gone")
	assert.False(t, refreshTokenExists(t, refreshToken.ID),
		"the ROPC refresh token must be removed with its client")
}

// =============================================================================
// Exhaustive: every table with a foreign key to the parent
// =============================================================================

// TestDeleteUser_RemovesAllDependentRows covers all ten tables that reference
// users(id), plus the two second-hop tables that hang off them
// (user_session_clients under user_sessions, refresh_tokens under codes).
func TestDeleteUser_RemovesAllDependentRows(t *testing.T) {
	user := createTestUser(t)
	client := createTestClient(t)

	// Direct children of users.
	code := createTestCode(t, client.ID, user.ID)
	ropcToken := createROPCRefreshToken(t, user.ID, client.ID)
	attribute := createTestUserAttribute(t, user.ID)
	consent := createTestUserConsentForUser(t, user.ID)
	session := createTestUserSessionWithClient(t, user.ID, client.ID)
	group := createTestGroup(t)
	userGroup := createTestUserGroupWithUserAndGroup(t, user.ID, group.ID)
	resource := createTestResource(t)
	permission := createTestPermission(t, resource)
	userPermission := createTestUserPermissionWithUserAndPermission(t, user.ID, permission.ID)
	profilePicture := createTestUserProfilePicture(t, user.ID)
	legalDocument := createLegalDocument(t, record.LegalDocumentKindMustAccept)
	acceptedVersion := publishVersion(t, legalDocument.ID, 1, "Terms of use", "Be nice.")
	acceptLegalDocumentVersion(t, user.ID, acceptedVersion.ID)
	recoveryCodes := recoveryCodeHashes(3)
	replaceRecoveryCodes(t, user.ID, recoveryCodes)
	require.True(t, useRecoveryCode(t, user.ID, recoveryCodes[0]), "sanity: one code of the set is used")
	require.Equal(t, 2, unusedRecoveryCodes(t, user.ID), "sanity: the other two codes are unused")

	// Second hop: a refresh token under the code, and the session's client row.
	codeLinkedToken := createCodeLinkedRefreshToken(t, code.ID)
	sessionClients, err := database.GetUserSessionClientsByUserSessionID(context.Background(), nil, session.ID)
	require.NoError(t, err, "GetUserSessionClientsByUserSessionID")
	require.Len(t, sessionClients, 1, "expected the session to have one client row")
	sessionClientID := sessionClients[0].ID

	require.NoError(t, database.DeleteUser(context.Background(), nil, user.ID), "DeleteUser")

	deletedUser, err := database.GetUserByID(context.Background(), nil, user.ID)
	require.NoError(t, err, "GetUserByID")
	require.Nil(t, deletedUser, "user must be gone")

	// codes
	deletedCode, err := database.GetCodeByID(context.Background(), nil, code.ID)
	require.NoError(t, err, "GetCodeByID")
	assert.Nil(t, deletedCode, "codes must cascade from users")

	// refresh_tokens, both shapes
	assert.False(t, refreshTokenExists(t, ropcToken.ID),
		"refresh_tokens must cascade from users (ROPC-shaped, code_id NULL)")
	assert.False(t, refreshTokenExists(t, codeLinkedToken.ID),
		"refresh_tokens must cascade from codes (auth-code-shaped)")

	// user_attributes
	deletedAttribute, err := database.GetUserAttributeByID(context.Background(), nil, attribute.ID)
	require.NoError(t, err, "GetUserAttributeByID")
	assert.Nil(t, deletedAttribute, "user_attributes must cascade from users")

	// user_consents
	deletedConsent, err := database.GetUserConsentByID(context.Background(), nil, consent.ID)
	require.NoError(t, err, "GetUserConsentByID")
	assert.Nil(t, deletedConsent, "user_consents must cascade from users")

	// user_sessions
	deletedSession, err := database.GetUserSessionByID(context.Background(), nil, session.ID)
	require.NoError(t, err, "GetUserSessionByID")
	assert.Nil(t, deletedSession, "user_sessions must cascade from users")

	// user_session_clients (second hop, under user_sessions)
	deletedSessionClient, err := database.GetUserSessionClientByID(context.Background(), nil, sessionClientID)
	require.NoError(t, err, "GetUserSessionClientByID")
	assert.Nil(t, deletedSessionClient, "user_session_clients must cascade from user_sessions")

	// users_groups
	deletedUserGroup, err := database.GetUserGroupByID(context.Background(), nil, userGroup.ID)
	require.NoError(t, err, "GetUserGroupByID")
	assert.Nil(t, deletedUserGroup, "users_groups must cascade from users")

	// users_permissions
	deletedUserPermission, err := database.GetUserPermissionByID(context.Background(), nil, userPermission.ID)
	require.NoError(t, err, "GetUserPermissionByID")
	assert.Nil(t, deletedUserPermission, "users_permissions must cascade from users")

	// user_profile_pictures
	deletedPicture, err := database.GetUserProfilePictureByUserID(context.Background(), nil, user.ID)
	require.NoError(t, err, "GetUserProfilePictureByUserID")
	assert.Nil(t, deletedPicture, "user_profile_pictures must cascade from users")
	assert.NotZero(t, profilePicture.ID, "sanity: the fixture was created")

	// legal_document_acceptances
	assert.Empty(t, acceptedVersionIDs(t, user.ID), "legal_document_acceptances must cascade from users")

	// user_recovery_codes, the used code and the unused ones alike
	for i, codeHash := range recoveryCodes {
		exists, existsErr := database.UserRecoveryCodeExists(context.Background(), nil, user.ID, codeHash)
		require.NoError(t, existsErr, "UserRecoveryCodeExists")
		assert.False(t, exists, "user_recovery_codes must cascade from users (code %d)", i)
	}
	assert.Zero(t, unusedRecoveryCodes(t, user.ID), "no unused recovery code may outlive its user")

	// The group, resource and permission are independent of the user and must
	// survive: cascade must not travel up an association table.
	survivingGroup, err := database.GetGroupByID(context.Background(), nil, group.ID)
	require.NoError(t, err, "GetGroupByID")
	assert.NotNil(t, survivingGroup, "deleting a user must not delete the group")
	survivingPermission, err := database.GetPermissionByID(context.Background(), nil, permission.ID)
	require.NoError(t, err, "GetPermissionByID")
	assert.NotNil(t, survivingPermission, "deleting a user must not delete the permission")
	survivingClient, err := database.GetClientByID(context.Background(), nil, client.ID)
	require.NoError(t, err, "GetClientByID")
	assert.NotNil(t, survivingClient, "deleting a user must not delete the client")
	survivingVersion, err := database.GetLegalDocumentVersion(context.Background(), nil, legalDocument.ID, 1)
	require.NoError(t, err, "GetLegalDocumentVersion")
	assert.NotNil(t, survivingVersion, "deleting a user must not delete the version they accepted")
}

// TestDeleteClient_RemovesAllDependentRows covers all eight tables that
// reference clients(id).
func TestDeleteClient_RemovesAllDependentRows(t *testing.T) {
	user := createTestUser(t)
	client := createTestClient(t)

	code := createTestCode(t, client.ID, user.ID)
	ropcToken := createROPCRefreshToken(t, user.ID, client.ID)
	redirectURI := createTestRedirectURI(t, client.ID)
	webOrigin := createTestWebOrigin(t, client.ID)
	logo := createTestClientLogo(t, client.ID)

	resource := createTestResource(t)
	permission := createTestPermission(t, resource)
	clientPermission := &record.ClientPermission{
		ClientID:     client.ID,
		PermissionID: permission.ID,
	}
	require.NoError(t, database.CreateClientPermission(context.Background(), nil, clientPermission), "CreateClientPermission")

	consent := &record.UserConsent{
		UserID:   user.ID,
		ClientID: client.ID,
		Scope:    "openid profile",
	}
	require.NoError(t, database.CreateUserConsent(context.Background(), nil, consent), "CreateUserConsent")

	session := createTestUserSessionWithClient(t, user.ID, client.ID)
	sessionClients, err := database.GetUserSessionClientsByUserSessionID(context.Background(), nil, session.ID)
	require.NoError(t, err, "GetUserSessionClientsByUserSessionID")
	require.Len(t, sessionClients, 1, "expected the session to have one client row")
	sessionClientID := sessionClients[0].ID

	legalDocument := createLegalDocument(t, record.LegalDocumentKindMustAccept)
	linkDocumentToClient(t, legalDocument.ID, client.ID)

	require.NoError(t, database.DeleteClient(context.Background(), nil, client.ID), "DeleteClient")

	deletedClient, err := database.GetClientByID(context.Background(), nil, client.ID)
	require.NoError(t, err, "GetClientByID")
	require.Nil(t, deletedClient, "client must be gone")

	// codes
	deletedCode, err := database.GetCodeByID(context.Background(), nil, code.ID)
	require.NoError(t, err, "GetCodeByID")
	assert.Nil(t, deletedCode, "codes must cascade from clients")

	// refresh_tokens
	assert.False(t, refreshTokenExists(t, ropcToken.ID),
		"refresh_tokens must cascade from clients (ROPC-shaped, code_id NULL)")

	// redirect_uris
	deletedRedirectURI, err := database.GetRedirectURIByID(context.Background(), nil, redirectURI.ID)
	require.NoError(t, err, "GetRedirectURIByID")
	assert.Nil(t, deletedRedirectURI, "redirect_uris must cascade from clients")

	// web_origins
	deletedWebOrigin, err := database.GetWebOriginByID(context.Background(), nil, webOrigin.ID)
	require.NoError(t, err, "GetWebOriginByID")
	assert.Nil(t, deletedWebOrigin, "web_origins must cascade from clients")

	// client_logos
	deletedLogo, err := database.GetClientLogoByClientID(context.Background(), nil, client.ID)
	require.NoError(t, err, "GetClientLogoByClientID")
	assert.Nil(t, deletedLogo, "client_logos must cascade from clients")
	assert.NotZero(t, logo.ID, "sanity: the fixture was created")

	// clients_permissions
	deletedClientPermission, err := database.GetClientPermissionByID(context.Background(), nil, clientPermission.ID)
	require.NoError(t, err, "GetClientPermissionByID")
	assert.Nil(t, deletedClientPermission, "clients_permissions must cascade from clients")

	// user_consents
	deletedConsent, err := database.GetUserConsentByID(context.Background(), nil, consent.ID)
	require.NoError(t, err, "GetUserConsentByID")
	assert.Nil(t, deletedConsent, "user_consents must cascade from clients")

	// user_session_clients
	deletedSessionClient, err := database.GetUserSessionClientByID(context.Background(), nil, sessionClientID)
	require.NoError(t, err, "GetUserSessionClientByID")
	assert.Nil(t, deletedSessionClient, "user_session_clients must cascade from clients")

	// legal_documents_clients
	assert.Empty(t, linkedClientIDs(t, legalDocument.ID), "legal_documents_clients must cascade from clients")

	// The user, its session, the permission and the legal document are independent of the client.
	survivingUser, err := database.GetUserByID(context.Background(), nil, user.ID)
	require.NoError(t, err, "GetUserByID")
	assert.NotNil(t, survivingUser, "deleting a client must not delete the user")
	survivingSession, err := database.GetUserSessionByID(context.Background(), nil, session.ID)
	require.NoError(t, err, "GetUserSessionByID")
	assert.NotNil(t, survivingSession, "deleting a client must not delete the user session")
	survivingPermission, err := database.GetPermissionByID(context.Background(), nil, permission.ID)
	require.NoError(t, err, "GetPermissionByID")
	assert.NotNil(t, survivingPermission, "deleting a client must not delete the permission")
	survivingDocument, err := database.GetLegalDocumentByID(context.Background(), nil, legalDocument.ID)
	require.NoError(t, err, "GetLegalDocumentByID")
	assert.NotNil(t, survivingDocument, "deleting a client must not delete a legal document it was listed on")
}
