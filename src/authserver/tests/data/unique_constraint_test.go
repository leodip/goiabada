package datatests

import (
	"database/sql"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Unique constraints.
//
// The schema declares twelve of them, and like the cascade rules they are written
// out separately for each of the four engines, in one case as a named index and in
// another inline on the column. Nothing asserted that any of them actually bites,
// so a constraint missing from one dialect would have gone unnoticed. These are the
// invariants the auth flows lean on: two clients cannot share a client_identifier,
// two refresh tokens cannot share a jti, a code hash cannot be reused, and only one
// signing key can be in any given state.
//
// Only the fact of an error is asserted, never its text, which differs per engine
// (mysql "Duplicate entry", postgres "duplicate key value violates unique
// constraint", mssql "Cannot insert duplicate key row", sqlite "UNIQUE constraint
// failed").
//
// Note what is NOT here: users.username. It is unique in no engine's schema, and is
// enforced only by profile_validator's read-then-write check. That is a real
// (if narrow) gap rather than something to pin as intended behaviour, so it is
// called out rather than asserted either way.

func TestUnique_ClientIdentifier(t *testing.T) {
	existing := createTestClient(t)

	duplicate := &models.Client{
		ClientIdentifier: existing.ClientIdentifier,
		Description:      "Duplicate client identifier",
	}
	err := database.CreateClient(nil, duplicate)
	assert.Error(t, err, "two clients must not share a client_identifier")
}

func TestUnique_ResourceIdentifier(t *testing.T) {
	existing := createTestResource(t)

	duplicate := &models.Resource{
		ResourceIdentifier: existing.ResourceIdentifier,
		Description:        "Duplicate resource identifier",
	}
	err := database.CreateResource(nil, duplicate)
	assert.Error(t, err, "two resources must not share a resource_identifier")
}

func TestUnique_GroupIdentifier(t *testing.T) {
	existing := createTestGroup(t)

	duplicate := &models.Group{
		GroupIdentifier: existing.GroupIdentifier,
		Description:     "Duplicate group identifier",
	}
	err := database.CreateGroup(nil, duplicate)
	assert.Error(t, err, "two groups must not share a group_identifier")
}

func TestUnique_UserSubject(t *testing.T) {
	existing := createTestUser(t)

	duplicate := &models.User{
		Enabled:  true,
		Subject:  existing.Subject,
		Username: gofakeit.Username(),
		Email:    "dup_subject_" + gofakeit.LetterN(10) + "@example.com",
	}
	err := database.CreateUser(nil, duplicate)
	assert.Error(t, err, "two users must not share a subject")
}

func TestUnique_UserEmail(t *testing.T) {
	existing := createTestUser(t)

	duplicate := &models.User{
		Enabled:  true,
		Subject:  uuid.New(),
		Username: gofakeit.Username(),
		Email:    existing.Email,
	}
	err := database.CreateUser(nil, duplicate)
	assert.Error(t, err, "two users must not share an email")
}

func TestUnique_CodeHash(t *testing.T) {
	client := createTestClient(t)
	user := createTestUser(t)
	existing := createTestCode(t, client.Id, user.Id)

	duplicate := *existing
	duplicate.Id = 0
	duplicate.Code = "other_" + gofakeit.LetterN(6)
	err := database.CreateCode(nil, &duplicate)
	assert.Error(t, err, "two codes must not share a code_hash")
}

func TestUnique_KeyPairState(t *testing.T) {
	// 'next' rather than 'current', because 'next' is the only duplicate the rotation
	// defect could actually produce: two concurrent rotations both inserting a new next
	// key. The constraint covers all three states identically (#251).
	next := enums.KeyStateNext.String()
	existing := createKeyPairInState(t, next)

	duplicate := &models.KeyPair{
		State:         existing.State,
		KeyIdentifier: gofakeit.UUID(),
		Type:          "RSA",
		Algorithm:     "RS256",
	}
	err := database.CreateKeyPair(nil, duplicate)
	assert.Error(t, err, "two key pairs must not share a state")
}

func TestUnique_RefreshTokenJti(t *testing.T) {
	user := createTestUser(t)
	client := createTestClient(t)
	existing := createROPCRefreshToken(t, user.Id, client.Id)

	now := time.Now().UTC().Truncate(time.Microsecond)
	duplicate := &models.RefreshToken{
		UserId:           sql.NullInt64{Int64: user.Id, Valid: true},
		ClientId:         sql.NullInt64{Int64: client.Id, Valid: true},
		RefreshTokenJti:  existing.RefreshTokenJti,
		RefreshTokenType: "Offline",
		Scope:            "openid profile",
		IssuedAt:         sql.NullTime{Time: now, Valid: true},
		ExpiresAt:        sql.NullTime{Time: now.Add(time.Hour), Valid: true},
		MaxLifetime:      sql.NullTime{Time: now.Add(24 * time.Hour), Valid: true},
	}
	err := database.CreateRefreshToken(nil, duplicate)
	assert.Error(t, err, "two refresh tokens must not share a jti")
}

func TestUnique_UserSessionSessionIdentifier(t *testing.T) {
	user := createTestUser(t)
	existing := createTestUserSession(t, user.Id)

	now := time.Now().UTC().Truncate(time.Microsecond)
	duplicate := &models.UserSession{
		SessionIdentifier: existing.SessionIdentifier,
		Started:           now,
		LastAccessed:      now,
		AuthMethods:       "pwd",
		AcrLevel:          existing.AcrLevel,
		AuthTime:          now,
		UserId:            user.Id,
	}
	err := database.CreateUserSession(nil, duplicate)
	assert.Error(t, err, "two user sessions must not share a session_identifier")
}

// One profile picture per user: user_profile_pictures.user_id is unique (inline on
// the column in sqlite, as a named index elsewhere).
func TestUnique_UserProfilePicturePerUser(t *testing.T) {
	user := createTestUser(t)
	createTestUserProfilePicture(t, user.Id)

	duplicate := &models.UserProfilePicture{
		UserId:      user.Id,
		Picture:     createTestPNG(10, 10),
		ContentType: "image/png",
	}
	err := database.CreateUserProfilePicture(nil, duplicate)
	assert.Error(t, err, "a user must not have two profile pictures")
}

// One logo per client, same shape as the profile picture above.
func TestUnique_ClientLogoPerClient(t *testing.T) {
	client := createTestClient(t)
	createTestClientLogo(t, client.Id)

	duplicate := &models.ClientLogo{
		ClientId:    client.Id,
		Logo:        createTestPNG(10, 10),
		ContentType: "image/png",
	}
	err := database.CreateClientLogo(nil, duplicate)
	assert.Error(t, err, "a client must not have two logos")
}

// permissions is the only composite constraint: (permission_identifier,
// resource_id). Both halves are asserted, because the negative case alone would
// also pass if the index were mistakenly declared on permission_identifier only,
// and the whole permission model depends on the same identifier being reusable
// across resources.
func TestUnique_PermissionIdentifierPerResource(t *testing.T) {
	resource := createTestResource(t)
	existing := createTestPermission(t, resource)

	duplicate := &models.Permission{
		PermissionIdentifier: existing.PermissionIdentifier,
		Description:          "Duplicate permission on the same resource",
		ResourceId:           resource.Id,
	}
	err := database.CreatePermission(nil, duplicate)
	assert.Error(t, err, "a resource must not have two permissions with the same identifier")

	// The same identifier on a different resource is legitimate, and is what
	// makes permissions resource-scoped rather than global.
	otherResource := createTestResource(t)
	onOtherResource := &models.Permission{
		PermissionIdentifier: existing.PermissionIdentifier,
		Description:          "Same identifier, different resource",
		ResourceId:           otherResource.Id,
	}
	require.NoError(t, database.CreatePermission(nil, onOtherResource),
		"the same permission identifier must be allowed on a different resource")
	assert.NotZero(t, onOtherResource.Id, "expected the permission to be created")
}

// A rejected duplicate must leave no row behind, so a caller that ignores the
// error cannot end up having half-created something.
func TestUnique_RejectedDuplicateInsertsNothing(t *testing.T) {
	existing := createTestGroup(t)

	before, err := database.GetAllGroups(nil)
	require.NoError(t, err, "GetAllGroups")

	duplicate := &models.Group{
		GroupIdentifier: existing.GroupIdentifier,
		Description:     "Duplicate group identifier",
	}
	require.Error(t, database.CreateGroup(nil, duplicate), "expected the duplicate to be rejected")

	after, err := database.GetAllGroups(nil)
	require.NoError(t, err, "GetAllGroups")
	assert.Len(t, after, len(before), "a rejected duplicate must not add a row")
}
