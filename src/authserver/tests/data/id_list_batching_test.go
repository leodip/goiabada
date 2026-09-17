package datatests

import (
	"database/sql"
	"testing"
)

// absentIdBase is the first of a run of ids no row holds. Every table's ids are assigned by the
// engine from one, so a billion up is free, and padding with distinct values is what makes the
// parameter count the real one: a list of 2,101 repetitions of the same id is one parameter after
// deduplication and would prove nothing.
const absentIdBase = int64(1_000_000_000)

// TestIdListLookups_MoreIdsThanOneStatementCanCarry asks every id-list lookup in commondb for more
// ids than a single statement can bind.
//
// Every id in an IN list is a bound parameter, and SQL Server refuses a statement carrying more
// than 2,100 of them with error 8003, the lowest ceiling of the four engines, so an unbounded list
// answered a valid request with an error rather than its rows. #373 fixed that at GetClientsByIds,
// which is where the crash was noticed, and left twelve lookups in the same package expanding
// without a bound; they read long lists in several statements now, through forEachIdBatch, and
// this is the case that says so on every engine.
//
// One table rather than a case per file, because the property is one property and the thirteen
// lookups differ only in what they select. A new lookup adds a row here and the lint in
// src/core/data adds nothing by itself: it can see that forEachIdBatch is called and not that the
// IN list was built from the batch rather than from the whole list. This is what sees that.
//
// The two lengths are chosen: 2,101 is one past SQL Server's ceiling, and 2,000 is an exact
// multiple of the batch size, where an off-by-one in the loop bounds drops the final batch instead
// of failing loudly. The real ids sit in different batches in both, including the last slot, so a
// batch that is never issued loses a row the assertions are counting.
//
// GetClientsByIds keeps its own pair of cases in client_test.go: it was first, and it carries the
// repeated-id-across-a-boundary case that belongs to the deduplication rather than to the split.
// readEmailGroup is the one lookup absent here, because its list is the users whose address
// differs from another only by case, and a group of 2,101 of those cannot be built without 2,101
// accounts; its batching is pinned in commondb's own tier instead.
func TestIdListLookups_MoreIdsThanOneStatementCanCarry(t *testing.T) {
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
			name: "GetGroupsByIds",
			rows: func(t *testing.T) []int64 {
				return idsOfThree(func() int64 { return createTestGroup(t).Id })
			},
			answered: func(t *testing.T, ids []int64) []int64 {
				groups, err := database.GetGroupsByIds(nil, ids)
				requireNoLookupError(t, err)
				found := make([]int64, 0, len(groups))
				for _, group := range groups {
					found = append(found, group.Id)
				}
				return found
			},
		},
		{
			name: "GetGroupAttributesByGroupIds",
			rows: func(t *testing.T) []int64 {
				return idsOfThree(func() int64 {
					group := createTestGroup(t)
					createTestGroupAttribute(t, group.Id)
					return group.Id
				})
			},
			answered: func(t *testing.T, ids []int64) []int64 {
				attributes, err := database.GetGroupAttributesByGroupIds(nil, ids)
				requireNoLookupError(t, err)
				found := make([]int64, 0, len(attributes))
				for _, attribute := range attributes {
					found = append(found, attribute.GroupId)
				}
				return found
			},
		},
		{
			name: "GetGroupPermissionsByGroupIds",
			rows: func(t *testing.T) []int64 {
				resource := createTestResource(t)
				permission := createTestPermission(t, resource)
				return idsOfThree(func() int64 {
					group := createTestGroup(t)
					createTestGroupPermission(t, group.Id, permission.Id)
					return group.Id
				})
			},
			answered: func(t *testing.T, ids []int64) []int64 {
				groupPermissions, err := database.GetGroupPermissionsByGroupIds(nil, ids)
				requireNoLookupError(t, err)
				found := make([]int64, 0, len(groupPermissions))
				for _, groupPermission := range groupPermissions {
					found = append(found, groupPermission.GroupId)
				}
				return found
			},
		},
		{
			name: "GetPermissionsByIds",
			rows: func(t *testing.T) []int64 {
				resource := createTestResource(t)
				return idsOfThree(func() int64 { return createTestPermission(t, resource).Id })
			},
			answered: func(t *testing.T, ids []int64) []int64 {
				permissions, err := database.GetPermissionsByIds(nil, ids)
				requireNoLookupError(t, err)
				found := make([]int64, 0, len(permissions))
				for _, permission := range permissions {
					found = append(found, permission.Id)
				}
				return found
			},
		},
		{
			name: "GetResourcesByIds",
			rows: func(t *testing.T) []int64 {
				return idsOfThree(func() int64 { return createTestResource(t).Id })
			},
			answered: func(t *testing.T, ids []int64) []int64 {
				resources, err := database.GetResourcesByIds(nil, ids)
				requireNoLookupError(t, err)
				found := make([]int64, 0, len(resources))
				for _, resource := range resources {
					found = append(found, resource.Id)
				}
				return found
			},
		},
		{
			name: "GetUsersByIds",
			rows: func(t *testing.T) []int64 {
				return idsOfThree(func() int64 { return createTestUser(t).Id })
			},
			answered: func(t *testing.T, ids []int64) []int64 {
				users, err := database.GetUsersByIds(nil, ids)
				requireNoLookupError(t, err)
				found := make([]int64, 0, len(users))
				for id := range users {
					found = append(found, id)
				}
				return found
			},
		},
		{
			name: "GetUserGroupsByUserIds",
			rows: func(t *testing.T) []int64 {
				group := createTestGroup(t)
				return idsOfThree(func() int64 {
					user := createTestUser(t)
					createTestUserGroupWithUserAndGroup(t, user.Id, group.Id)
					return user.Id
				})
			},
			answered: func(t *testing.T, ids []int64) []int64 {
				userGroups, err := database.GetUserGroupsByUserIds(nil, ids)
				requireNoLookupError(t, err)
				found := make([]int64, 0, len(userGroups))
				for _, userGroup := range userGroups {
					found = append(found, userGroup.UserId)
				}
				return found
			},
		},
		{
			name: "GetUserPermissionsByUserIds",
			rows: func(t *testing.T) []int64 {
				resource := createTestResource(t)
				permission := createTestPermission(t, resource)
				return idsOfThree(func() int64 {
					user := createTestUser(t)
					createTestUserPermissionWithUserAndPermission(t, user.Id, permission.Id)
					return user.Id
				})
			},
			answered: func(t *testing.T, ids []int64) []int64 {
				userPermissions, err := database.GetUserPermissionsByUserIds(nil, ids)
				requireNoLookupError(t, err)
				found := make([]int64, 0, len(userPermissions))
				for _, userPermission := range userPermissions {
					found = append(found, userPermission.UserId)
				}
				return found
			},
		},
		{
			name: "GetUserSessionClientsByUserSessionIds",
			rows: func(t *testing.T) []int64 {
				client := createTestClient(t)
				return idsOfThree(func() int64 {
					user := createTestUser(t)
					session := createTestUserSession(t, user.Id)
					createTestUserSessionClientWithIds(t, session.Id, client.Id)
					return session.Id
				})
			},
			answered: func(t *testing.T, ids []int64) []int64 {
				sessionClients, err := database.GetUserSessionClientsByUserSessionIds(nil, ids)
				requireNoLookupError(t, err)
				found := make([]int64, 0, len(sessionClients))
				for _, sessionClient := range sessionClients {
					found = append(found, sessionClient.UserSessionId)
				}
				return found
			},
		},
		{
			name: "GetUserSessionsClientByIds",
			rows: func(t *testing.T) []int64 {
				client := createTestClient(t)
				return idsOfThree(func() int64 {
					user := createTestUser(t)
					session := createTestUserSession(t, user.Id)
					return createTestUserSessionClientWithIds(t, session.Id, client.Id).Id
				})
			},
			answered: func(t *testing.T, ids []int64) []int64 {
				sessionClients, err := database.GetUserSessionsClientByIds(nil, ids)
				requireNoLookupError(t, err)
				found := make([]int64, 0, len(sessionClients))
				for _, sessionClient := range sessionClients {
					found = append(found, sessionClient.Id)
				}
				return found
			},
		},
		{
			// The one write in the family. It answers nothing, so the rows are read back and the
			// ones carrying the new generation are what the list reached.
			name: "PromoteRefreshTokenGenerations",
			rows: func(t *testing.T) []int64 {
				return idsOfThree(func() int64 { return createTestRefreshToken(t).Id })
			},
			answered: func(t *testing.T, ids []int64) []int64 {
				const generation = int64(4242)
				err := database.RunInTransaction(func(tx *sql.Tx) error {
					return database.PromoteRefreshTokenGenerations(tx, ids, generation)
				})
				requireNoLookupError(t, err)

				found := make([]int64, 0, 3)
				for _, id := range ids {
					if id >= absentIdBase {
						continue
					}
					token, err := database.GetRefreshTokenById(nil, id)
					requireNoLookupError(t, err)
					if token != nil && token.AuthStateGeneration == generation {
						found = append(found, token.Id)
					}
				}
				return found
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			realIds := testCase.rows(t)
			if len(realIds) != 3 {
				t.Fatalf("the fixture must create three rows, it created %d", len(realIds))
			}

			for _, length := range lengths {
				t.Run(length.name, func(t *testing.T) {
					ids := make([]int64, length.total)
					for i := range ids {
						ids[i] = absentIdBase + int64(i)
					}
					for i, position := range length.positions {
						ids[position] = realIds[i]
					}

					found := testCase.answered(t, ids)

					for _, realId := range realIds {
						if !containsId(found, realId) {
							t.Errorf("the list named id %d and the answer does not carry it: %v", realId, found)
						}
					}
					for _, id := range found {
						if id >= absentIdBase {
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

func containsId(ids []int64, wanted int64) bool {
	for _, id := range ids {
		if id == wanted {
			return true
		}
	}
	return false
}
