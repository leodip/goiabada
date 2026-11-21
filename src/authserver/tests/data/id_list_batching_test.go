package datatests

import (
	"context"
	"database/sql"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
)

// absentIDBase is the first of a run of ids no row holds. Every table's ids are assigned by the
// engine from one, so a billion up is free, and padding with distinct values is what makes the
// parameter count the real one: a list of 2,101 repetitions of the same id is one parameter after
// deduplication and would prove nothing.
const absentIDBase = int64(1_000_000_000)

// TestIDListLookups_MoreIDsThanOneStatementCanCarry asks every id-list lookup in commondb for more
// ids than a single statement can bind.
//
// Every id in an IN list is a bound parameter, and SQL Server refuses a statement carrying more
// than 2,100 of them with error 8003, the lowest ceiling of the four engines, so an unbounded list
// answered a valid request with an error rather than its rows. #373 fixed that at GetClientsByIDs,
// which is where the crash was noticed, and left twelve lookups in the same package expanding
// without a bound; they read long lists in several statements now, through forEachIDBatch, and
// this is the case that says so on every engine.
//
// One table rather than a case per file, because the property is one property and the thirteen
// lookups differ only in what they select. A new lookup adds a row here and the lint in
// src/authserver/internal/data adds nothing by itself: it can see that forEachIDBatch is called
// and not that the IN list was built from the batch rather than from the whole list. This is
// what sees that.
//
// The two lengths are chosen: 2,101 is one past SQL Server's ceiling, and 2,000 is an exact
// multiple of the batch size, where an off-by-one in the loop bounds drops the final batch instead
// of failing loudly. The real ids sit in different batches in both, including the last slot, so a
// batch that is never issued loses a row the assertions are counting.
//
// GetClientsByIDs keeps its own pair of cases in client_test.go: it was first, and it carries the
// repeated-id-across-a-boundary case that belongs to the deduplication rather than to the split.
// readEmailGroup is the one lookup absent here, because its list is the users whose address
// differs from another only by case, and a group of 2,101 of those cannot be built without 2,101
// accounts; its batching is pinned in commondb's own tier instead.
func TestIDListLookups_MoreIDsThanOneStatementCanCarry(t *testing.T) {
	lengths := []struct {
		name string
		// total is how many ids the list carries, real and padding together.
		total int
		// positions are where in that list the three real ids are placed.
		positions []int
	}{
		{name: "one past SQL Server's 2,100 parameter ceiling", total: 2101, positions: []int{0, 1500, 2100}},
		{name: "an exact multiple of the batch size", total: 2000, positions: []int{0, 999, 1999}},
	}

	testCases := []struct {
		name string
		// rows creates three rows and returns the three ids the list will name: the rows' own ids
		// where the lookup selects by primary key, and their parents' where it selects by a
		// foreign key.
		rows func(t *testing.T) []int64
		// answered runs the lookup with the padded list and returns, out of what came back, the
		// ids the list named.
		answered func(t *testing.T, ids []int64) []int64
	}{
		{
			name: "GetGroupsByIDs",
			rows: func(t *testing.T) []int64 {
				return idsOfThree(func() int64 { return createTestGroup(t).ID })
			},
			answered: func(t *testing.T, ids []int64) []int64 {
				groups, err := database.GetGroupsByIDs(context.Background(), nil, ids)
				requireNoLookupError(t, err)
				found := make([]int64, 0, len(groups))
				for _, group := range groups {
					found = append(found, group.ID)
				}
				return found
			},
		},
		{
			name: "GetGroupAttributesByGroupIDs",
			rows: func(t *testing.T) []int64 {
				return idsOfThree(func() int64 {
					group := createTestGroup(t)
					createTestGroupAttribute(t, group.ID)
					return group.ID
				})
			},
			answered: func(t *testing.T, ids []int64) []int64 {
				attributes, err := database.GetGroupAttributesByGroupIDs(context.Background(), nil, ids)
				requireNoLookupError(t, err)
				found := make([]int64, 0, len(attributes))
				for _, attribute := range attributes {
					found = append(found, attribute.GroupID)
				}
				return found
			},
		},
		{
			name: "GetGroupPermissionsByGroupIDs",
			rows: func(t *testing.T) []int64 {
				resource := createTestResource(t)
				permission := createTestPermission(t, resource)
				return idsOfThree(func() int64 {
					group := createTestGroup(t)
					createTestGroupPermission(t, group.ID, permission.ID)
					return group.ID
				})
			},
			answered: func(t *testing.T, ids []int64) []int64 {
				groupPermissions, err := database.GetGroupPermissionsByGroupIDs(context.Background(), nil, ids)
				requireNoLookupError(t, err)
				found := make([]int64, 0, len(groupPermissions))
				for _, groupPermission := range groupPermissions {
					found = append(found, groupPermission.GroupID)
				}
				return found
			},
		},
		{
			name: "GetPermissionsByIDs",
			rows: func(t *testing.T) []int64 {
				resource := createTestResource(t)
				return idsOfThree(func() int64 { return createTestPermission(t, resource).ID })
			},
			answered: func(t *testing.T, ids []int64) []int64 {
				permissions, err := database.GetPermissionsByIDs(context.Background(), nil, ids)
				requireNoLookupError(t, err)
				found := make([]int64, 0, len(permissions))
				for _, permission := range permissions {
					found = append(found, permission.ID)
				}
				return found
			},
		},
		{
			name: "GetResourcesByIDs",
			rows: func(t *testing.T) []int64 {
				return idsOfThree(func() int64 { return createTestResource(t).ID })
			},
			answered: func(t *testing.T, ids []int64) []int64 {
				resources, err := database.GetResourcesByIDs(context.Background(), nil, ids)
				requireNoLookupError(t, err)
				found := make([]int64, 0, len(resources))
				for _, resource := range resources {
					found = append(found, resource.ID)
				}
				return found
			},
		},
		{
			name: "GetBrandAssetsByIDs",
			rows: func(t *testing.T) []int64 {
				return idsOfThree(func() int64 { return createTestBrandAsset(t, database, record.BrandAssetKindLogo).ID })
			},
			answered: func(t *testing.T, ids []int64) []int64 {
				assets, err := database.GetBrandAssetsByIDs(context.Background(), nil, ids)
				requireNoLookupError(t, err)
				found := make([]int64, 0, len(assets))
				for _, asset := range assets {
					found = append(found, asset.ID)
				}
				return found
			},
		},
		{
			name: "GetUsersByIDs",
			rows: func(t *testing.T) []int64 {
				return idsOfThree(func() int64 { return createTestUser(t).ID })
			},
			answered: func(t *testing.T, ids []int64) []int64 {
				users, err := database.GetUsersByIDs(context.Background(), nil, ids)
				requireNoLookupError(t, err)
				found := make([]int64, 0, len(users))
				for id := range users {
					found = append(found, id)
				}
				return found
			},
		},
		{
			name: "GetUserGroupsByUserIDs",
			rows: func(t *testing.T) []int64 {
				group := createTestGroup(t)
				return idsOfThree(func() int64 {
					user := createTestUser(t)
					createTestUserGroupWithUserAndGroup(t, user.ID, group.ID)
					return user.ID
				})
			},
			answered: func(t *testing.T, ids []int64) []int64 {
				userGroups, err := database.GetUserGroupsByUserIDs(context.Background(), nil, ids)
				requireNoLookupError(t, err)
				found := make([]int64, 0, len(userGroups))
				for _, userGroup := range userGroups {
					found = append(found, userGroup.UserID)
				}
				return found
			},
		},
		{
			name: "GetUserPermissionsByUserIDs",
			rows: func(t *testing.T) []int64 {
				resource := createTestResource(t)
				permission := createTestPermission(t, resource)
				return idsOfThree(func() int64 {
					user := createTestUser(t)
					createTestUserPermissionWithUserAndPermission(t, user.ID, permission.ID)
					return user.ID
				})
			},
			answered: func(t *testing.T, ids []int64) []int64 {
				userPermissions, err := database.GetUserPermissionsByUserIDs(context.Background(), nil, ids)
				requireNoLookupError(t, err)
				found := make([]int64, 0, len(userPermissions))
				for _, userPermission := range userPermissions {
					found = append(found, userPermission.UserID)
				}
				return found
			},
		},
		{
			name: "GetUserSessionClientsByUserSessionIDs",
			rows: func(t *testing.T) []int64 {
				client := createTestClient(t)
				return idsOfThree(func() int64 {
					user := createTestUser(t)
					session := createTestUserSession(t, user.ID)
					createTestUserSessionClientWithIDs(t, session.ID, client.ID)
					return session.ID
				})
			},
			answered: func(t *testing.T, ids []int64) []int64 {
				sessionClients, err := database.GetUserSessionClientsByUserSessionIDs(context.Background(), nil, ids)
				requireNoLookupError(t, err)
				found := make([]int64, 0, len(sessionClients))
				for _, sessionClient := range sessionClients {
					found = append(found, sessionClient.UserSessionID)
				}
				return found
			},
		},
		{
			name: "GetUserSessionsClientByIDs",
			rows: func(t *testing.T) []int64 {
				client := createTestClient(t)
				return idsOfThree(func() int64 {
					user := createTestUser(t)
					session := createTestUserSession(t, user.ID)
					return createTestUserSessionClientWithIDs(t, session.ID, client.ID).ID
				})
			},
			answered: func(t *testing.T, ids []int64) []int64 {
				sessionClients, err := database.GetUserSessionsClientByIDs(context.Background(), nil, ids)
				requireNoLookupError(t, err)
				found := make([]int64, 0, len(sessionClients))
				for _, sessionClient := range sessionClients {
					found = append(found, sessionClient.ID)
				}
				return found
			},
		},
		{
			// The one write in the family. It answers nothing, so the rows are read back and the
			// ones carrying the new generation are what the list reached.
			name: "PromoteRefreshTokenGenerations",
			rows: func(t *testing.T) []int64 {
				return idsOfThree(func() int64 { return createTestRefreshToken(t).ID })
			},
			answered: func(t *testing.T, ids []int64) []int64 {
				const generation = int64(4242)
				err := database.RunInTransaction(context.Background(), func(tx *sql.Tx) error {
					return database.PromoteRefreshTokenGenerations(context.Background(), tx, ids, generation)
				})
				requireNoLookupError(t, err)

				found := make([]int64, 0, 3)
				for _, id := range ids {
					if id >= absentIDBase {
						continue
					}
					token, err := database.GetRefreshTokenByID(context.Background(), nil, id)
					requireNoLookupError(t, err)
					if token != nil && token.AuthStateGeneration == generation {
						found = append(found, token.ID)
					}
				}
				return found
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			realIDs := testCase.rows(t)
			if len(realIDs) != 3 {
				t.Fatalf("the fixture must create three rows, it created %d", len(realIDs))
			}

			for _, length := range lengths {
				t.Run(length.name, func(t *testing.T) {
					ids := make([]int64, length.total)
					for i := range ids {
						ids[i] = absentIDBase + int64(i)
					}
					for i, position := range length.positions {
						ids[position] = realIDs[i]
					}

					found := testCase.answered(t, ids)

					for _, realID := range realIDs {
						if !containsID(found, realID) {
							t.Errorf("the list named id %d and the answer does not carry it: %v", realID, found)
						}
					}
					for _, id := range found {
						if id >= absentIDBase {
							t.Errorf("the answer carries id %d, which no row holds", id)
						}
					}
				})
			}
		})
	}
}

// idsOfThree runs create three times and collects what it returned, which is the shape every row
// in the table above builds its fixture with.
func idsOfThree(create func() int64) []int64 {
	ids := make([]int64, 0, 3)
	for i := 0; i < 3; i++ {
		ids = append(ids, create())
	}
	return ids
}

// requireNoLookupError stops the case on the failure it exists to catch. Before the split, a list
// past the ceiling came back from SQL Server as error 8003 rather than as rows, and a case that
// carried on to the assertions would report a missing row instead of the refusal that caused it.
func requireNoLookupError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("the lookup answered an error rather than its rows: %v", err)
	}
}

func containsID(ids []int64, wanted int64) bool {
	for _, id := range ids {
		if id == wanted {
			return true
		}
	}
	return false
}
