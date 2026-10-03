package apiclient

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The consents page reads the client's identifier and description off the consent itself, where it
// used to read them off a record.Client the console assembled beside it, and it dates each row from
// grantedAt. All three are flat keys on the wire and none of them is the consent's own id, so a
// decode that filled the id and nothing else would render a table of blank rows.
func TestAuthServerClient_GetUserConsentsDecodesTheClientColumnsAndTheGrant(t *testing.T) {
	client, recorded := serves(t, `{"consents":[{"id":5,"clientId":3,"userId":42,"scope":"openid profile",`+
		`"grantedAt":"2026-02-03T04:05:06Z","clientIdentifier":"web-app","clientDescription":"The web app"},`+
		`{"id":6,"clientId":4,"userId":42,"scope":"openid","grantedAt":null,"clientIdentifier":"other"}]}`)

	consents, err := client.GetUserConsents(context.Background(), "an-access-token", 42)
	require.NoError(t, err)

	gotPath, _ := recorded()
	assert.Equal(t, "/api/v1/admin/users/42/consents", gotPath)

	require.Len(t, consents, 2)
	assert.Equal(t, int64(5), consents[0].Id)
	assert.Equal(t, "openid profile", consents[0].Scope)
	assert.Equal(t, "web-app", consents[0].ClientIdentifier)
	assert.Equal(t, "The web app", consents[0].ClientDescription)
	require.NotNil(t, consents[0].GrantedAt)
	assert.Equal(t, time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC), consents[0].GrantedAt.UTC())

	assert.Nil(t, consents[1].GrantedAt, "an absent grant must reach the handler as nil rather than as a zero time")
}
