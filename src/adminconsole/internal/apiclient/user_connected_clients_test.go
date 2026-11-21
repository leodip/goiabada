package apiclient

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The user's Connected clients tab reads each row's client, its consent when there is one, and the
// scopes its live grants hold (#135 decision 4). A client with no consent arrives with a null
// consent, which must reach the page as nil rather than as an empty consent: the page says that
// client was never asked.
func TestAuthServerClient_GetUserConnectedClientsDecodesEachRow(t *testing.T) {
	client, recorded := serves(t, `{"clients":[`+
		`{"clientId":3,"clientIdentifier":"web-app","clientName":"Web app","clientNameUnverified":false,`+
		`"clientDescription":"The web app","consent":{"id":5,"scope":"openid profile","grantedAt":"2026-02-03T04:05:06Z"},`+
		`"grantScope":"openid","isCurrent":false},`+
		`{"clientId":4,"clientIdentifier":"payroll","clientName":"Payroll","clientNameUnverified":true,`+
		`"clientDescription":"","consent":null,"grantScope":"openid email","isCurrent":true}]}`)

	clients, err := client.GetUserConnectedClients(context.Background(), "an-access-token", 42)
	require.NoError(t, err)

	gotPath, _ := recorded()
	assert.Equal(t, "/api/v1/admin/users/42/connected-clients", gotPath)

	require.Len(t, clients, 2)
	assert.Equal(t, int64(3), clients[0].ClientID)
	assert.Equal(t, "web-app", clients[0].ClientIdentifier)
	assert.Equal(t, "The web app", clients[0].ClientDescription)
	require.NotNil(t, clients[0].Consent)
	assert.Equal(t, int64(5), clients[0].Consent.ID)
	assert.Equal(t, "openid profile", clients[0].Consent.Scope)
	require.NotNil(t, clients[0].Consent.GrantedAt)
	assert.Equal(t, time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC), clients[0].Consent.GrantedAt.UTC())
	assert.Equal(t, "openid", clients[0].GrantScope)
	assert.False(t, clients[0].IsCurrent)

	assert.Equal(t, int64(4), clients[1].ClientID)
	assert.True(t, clients[1].ClientNameUnverified)
	assert.Nil(t, clients[1].Consent, "a client never asked for consent has none")
	assert.Equal(t, "openid email", clients[1].GrantScope)
	assert.True(t, clients[1].IsCurrent)
}
