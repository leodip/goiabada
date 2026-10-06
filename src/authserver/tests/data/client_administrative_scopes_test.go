package datatests

import (
	"context"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClientAdministrativeScopesAllowed_RoundTrips holds the allowance to what CreateClient wrote,
// through every reader of a client row, both ways round (#499 decision 3). A client created with no
// word on it starts not allowed, which is what an administrator's create and dynamic client
// registration both rely on.
func TestClientAdministrativeScopesAllowed_RoundTrips(t *testing.T) {
	ctx := context.Background()

	allowed := createAllowanceTestClient(t, true)
	notAllowed := createAllowanceTestClient(t, false)
	unspecified := &record.Client{ClientIdentifier: "allowance_unset_" + fake.LetterN(6), Description: "Allowance test client"}
	require.NoError(t, database.CreateClient(ctx, nil, unspecified))

	want := map[int64]bool{allowed.Id: true, notAllowed.Id: false, unspecified.Id: false}

	for id, w := range want {
		byId, err := database.GetClientById(ctx, nil, id)
		require.NoError(t, err)
		require.NotNil(t, byId)
		assert.Equalf(t, w, byId.AdministrativeScopesAllowed, "GetClientById(%d)", id)

		byIdentifier, err := database.GetClientByClientIdentifier(ctx, nil, byId.ClientIdentifier)
		require.NoError(t, err)
		require.NotNil(t, byIdentifier)
		assert.Equalf(t, w, byIdentifier.AdministrativeScopesAllowed, "GetClientByClientIdentifier(%q)", byId.ClientIdentifier)
	}

	byIds, err := database.GetClientsByIds(ctx, nil, []int64{allowed.Id, notAllowed.Id, unspecified.Id})
	require.NoError(t, err)
	require.Len(t, byIds, 3)
	for _, c := range byIds {
		assert.Equalf(t, want[c.Id], c.AdministrativeScopesAllowed, "GetClientsByIds, client %d", c.Id)
	}

	all, err := database.GetAllClients(ctx, nil)
	require.NoError(t, err)
	seen := 0
	for _, c := range all {
		if w, ok := want[c.Id]; ok {
			seen++
			assert.Equalf(t, w, c.AdministrativeScopesAllowed, "GetAllClients, client %d", c.Id)
		}
	}
	assert.Equal(t, 3, seen, "GetAllClients must answer the three clients this test created")
}

// TestUpdateClient_LeavesTheAdministrativeScopesAllowanceAlone holds the whole-row client save to
// never writing the allowance, in either direction (#499 decisions 4 and 5). The settings,
// authentication and token saves all go through UpdateClient from a row read earlier in the
// request, and a manage-clients token can make every one of them: if the allowance rode along, a
// save racing an operator's switch would write back the value it read, and an allowance withdrawn
// in between would come back on. Only its own writer changes it.
func TestUpdateClient_LeavesTheAdministrativeScopesAllowanceAlone(t *testing.T) {
	ctx := context.Background()

	for _, stored := range []bool{true, false} {
		client := createAllowanceTestClient(t, stored)

		client.AdministrativeScopesAllowed = !stored
		client.Description = "rewritten_" + fake.LetterN(6)
		require.NoError(t, database.UpdateClient(ctx, nil, client))

		got, err := database.GetClientById(ctx, nil, client.Id)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equalf(t, stored, got.AdministrativeScopesAllowed,
			"UpdateClient must not write administrative_scopes_allowed: stored %v, the save carried %v", stored, !stored)
		assert.Equal(t, client.Description, got.Description,
			"and the save still writes the ordinary columns, so the exclusion is targeted rather than a write that stopped landing")
	}
}

func createAllowanceTestClient(t *testing.T, allowed bool) *record.Client {
	t.Helper()
	client := &record.Client{
		ClientIdentifier:            "allowance_" + fake.LetterN(8),
		Description:                 "Allowance test client",
		AdministrativeScopesAllowed: allowed,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	return client
}
