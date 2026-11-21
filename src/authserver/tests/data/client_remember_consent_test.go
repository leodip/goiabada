package datatests

import (
	"context"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClientRememberConsent_RoundTrips holds Remember consent to what CreateClient wrote, through
// every reader of a client row, both ways round (#711 decision 7). A client created with no word on
// it starts off, which is what a public row inserted without the column relies on.
func TestClientRememberConsent_RoundTrips(t *testing.T) {
	ctx := context.Background()

	on := createRememberConsentTestClient(t, true, true)
	off := createRememberConsentTestClient(t, true, false)
	unspecified := &record.Client{ClientIdentifier: "remember_unset_" + fake.LetterN(6), Description: "Remember consent test client", IsPublic: true}
	require.NoError(t, database.CreateClient(ctx, nil, unspecified))

	want := map[int64]bool{on.ID: true, off.ID: false, unspecified.ID: false}

	for id, w := range want {
		byID, err := database.GetClientByID(ctx, nil, id)
		require.NoError(t, err)
		require.NotNil(t, byID)
		assert.Equalf(t, w, byID.RememberConsent, "GetClientByID(%d)", id)

		byIdentifier, err := database.GetClientByClientIdentifier(ctx, nil, byID.ClientIdentifier)
		require.NoError(t, err)
		require.NotNil(t, byIdentifier)
		assert.Equalf(t, w, byIdentifier.RememberConsent, "GetClientByClientIdentifier(%q)", byID.ClientIdentifier)
	}

	byIDs, err := database.GetClientsByIDs(ctx, nil, []int64{on.ID, off.ID, unspecified.ID})
	require.NoError(t, err)
	require.Len(t, byIDs, 3)
	for _, c := range byIDs {
		assert.Equalf(t, want[c.ID], c.RememberConsent, "GetClientsByIDs, client %d", c.ID)
	}

	all, err := database.GetAllClients(ctx, nil)
	require.NoError(t, err)
	seen := 0
	for _, c := range all {
		if w, ok := want[c.ID]; ok {
			seen++
			assert.Equalf(t, w, c.RememberConsent, "GetAllClients, client %d", c.ID)
		}
	}
	assert.Equal(t, 3, seen, "GetAllClients must answer the three clients this test created")
}

// TestUpdateClient_LeavesRememberConsentAlone holds the whole-row client save to never writing
// Remember consent, in either direction (#711 decision 5). The OAuth2 flows, Tokens and settings
// saves write through UpdateClient from a row read earlier in the request: if the column rode along,
// a save loaded while the client was confidential would write Remember consent on over a switch to
// public made meanwhile.
func TestUpdateClient_LeavesRememberConsentAlone(t *testing.T) {
	ctx := context.Background()

	for _, stored := range []bool{true, false} {
		client := createRememberConsentTestClient(t, true, stored)

		client.RememberConsent = !stored
		client.Description = "rewritten_" + fake.LetterN(6)
		require.NoError(t, database.UpdateClient(ctx, nil, client))

		got, err := database.GetClientByID(ctx, nil, client.ID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equalf(t, stored, got.RememberConsent,
			"UpdateClient must not write remember_consent: stored %v, the save carried %v", stored, !stored)
		assert.Equal(t, client.Description, got.Description,
			"and the save still writes the ordinary columns, so the exclusion is targeted rather than a write that stopped landing")
	}
}

// TestSetClientRememberConsent_SwitchesTheOneClient holds the column's own writer to switching it
// both ways on the client it names and on no other, leaving the client's other columns as they were.
func TestSetClientRememberConsent_SwitchesTheOneClient(t *testing.T) {
	ctx := context.Background()

	target := createRememberConsentTestClient(t, true, false)
	bystander := createRememberConsentTestClient(t, true, false)
	onBystander := createRememberConsentTestClient(t, true, true)

	for _, remember := range []bool{true, false, false, true} {
		require.NoError(t, database.SetClientRememberConsent(ctx, nil, target.ID, remember))

		got, err := database.GetClientByID(ctx, nil, target.ID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equalf(t, remember, got.RememberConsent, "the target after switching to %v", remember)
		assert.Equal(t, target.ClientIdentifier, got.ClientIdentifier)
		assert.Equal(t, target.Description, got.Description)
		assert.True(t, got.IsPublic, "the switch writes Remember consent alone, never the mode")

		for want, other := range map[bool]*record.Client{false: bystander, true: onBystander} {
			stored, err := database.GetClientByID(ctx, nil, other.ID)
			require.NoError(t, err)
			assert.Equalf(t, want, stored.RememberConsent, "client %d is not the one switched", other.ID)
		}
	}

	require.Error(t, database.SetClientRememberConsent(ctx, nil, 0, true),
		"a zero id is a caller bug rather than a filter")
}

// TestSetClientPublic_TurnsRememberConsentOffOnTheRealTransition holds the switch to public to
// turning Remember consent off in the write that decides the transition, and to keeping an
// administrator's choice when the client was already public (#711 decision 5).
func TestSetClientPublic_TurnsRememberConsentOffOnTheRealTransition(t *testing.T) {
	ctx := context.Background()

	t.Run("confidential to public turns it off", func(t *testing.T) {
		client := createRememberConsentTestClient(t, false, true)

		tx := beginTx(t)
		becamePublic, err := database.SetClientPublic(ctx, tx, client.ID)
		require.NoError(t, err)
		require.True(t, becamePublic)
		require.NoError(t, database.CommitTransaction(ctx, tx))

		stored, err := database.GetClientByID(ctx, nil, client.ID)
		require.NoError(t, err)
		require.NotNil(t, stored)
		assert.True(t, stored.IsPublic)
		assert.False(t, stored.RememberConsent,
			"a client switched to public has not had its identity vouched for, so Remember consent goes off")
	})

	t.Run("public saved public again keeps the administrator's choice", func(t *testing.T) {
		for _, stored := range []bool{true, false} {
			client := createRememberConsentTestClient(t, true, stored)

			tx := beginTx(t)
			becamePublic, err := database.SetClientPublic(ctx, tx, client.ID)
			require.NoError(t, err)
			require.False(t, becamePublic)
			require.NoError(t, database.CommitTransaction(ctx, tx))

			got, err := database.GetClientByID(ctx, nil, client.ID)
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equalf(t, stored, got.RememberConsent,
				"re-saving an already-public client must keep Remember consent %v", stored)
		}
	})
}

// TestSetClientPublic_TurnsRememberConsentOffOverACommittedConcurrentSwitchToConfidential is
// decision 5's race on a real engine. The client starts public with Remember consent on, and a save
// arrives to keep it public. While that save is in flight another administrator switches the client
// to confidential, which turns Remember consent on, and commits. The save then makes the client
// public again: that is a real transition, so it must leave Remember consent off, never the on the
// confidential switch wrote.
func TestSetClientPublic_TurnsRememberConsentOffOverACommittedConcurrentSwitchToConfidential(t *testing.T) {
	if dbType() == data.SQLite {
		t.Skip("sqlite is limited to one connection (SetMaxOpenConns(1)), so a second write " +
			"transaction queues behind the first instead of overlapping it")
	}
	ctx := context.Background()

	client := createRememberConsentTestClient(t, true, true)

	other := beginTx(t)
	client.IsPublic = false
	client.ClientSecretEncrypted = []byte("the-secret-the-other-request-just-set")
	require.NoError(t, database.UpdateClient(ctx, other, client))
	require.NoError(t, database.SetClientRememberConsent(ctx, other, client.ID, true))

	saver := beginTx(t)
	type outcome struct {
		becamePublic bool
		err          error
	}
	done := make(chan outcome, 1)
	go func() {
		becamePublic, err := database.SetClientPublic(ctx, saver, client.ID)
		done <- outcome{becamePublic, err}
	}()

	select {
	case o := <-done:
		t.Fatalf("SetClientPublic answered %v while another transaction held the row uncommitted", o.becamePublic)
	case <-time.After(500 * time.Millisecond):
	}

	require.NoError(t, database.CommitTransaction(ctx, other))

	var o outcome
	select {
	case o = <-done:
	case <-time.After(30 * time.Second):
		t.Fatalf("SetClientPublic never returned after the concurrent transaction committed")
	}
	require.NoError(t, o.err)
	require.True(t, o.becamePublic)
	require.NoError(t, database.CommitTransaction(ctx, saver))

	stored, err := database.GetClientByID(ctx, nil, client.ID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.True(t, stored.IsPublic)
	assert.False(t, stored.RememberConsent,
		"the save made a confidential client public, so it must leave Remember consent off")
}

func createRememberConsentTestClient(t *testing.T, isPublic, remember bool) *record.Client {
	t.Helper()
	client := &record.Client{
		ClientIdentifier: "remember_" + fake.LetterN(8),
		Description:      "Remember consent test client",
		IsPublic:         isPublic,
		RememberConsent:  remember,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	return client
}
