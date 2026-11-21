package render

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/api"
)

// The account sessions page and the admin user sessions page both render a session row from these
// fields, and each used to copy them by hand, which is how #281's UserAgent and #373's instants
// each had to land twice. One mapping now serves both, so every field is pinned here once, from
// literals rather than from the response the mapping read.
func TestSessionInfos_CarriesEveryFieldTheRowRenders(t *testing.T) {
	started := time.Date(2026, 9, 14, 21, 3, 0, 0, time.UTC)
	lastAccessed := time.Date(2026, 9, 17, 8, 45, 0, 0, time.UTC)

	got := SessionInfos([]api.UserSessionDetailResponse{{
		UserSessionResponse: api.UserSessionResponse{
			ID:                41,
			SessionIdentifier: "sid-41",
			Started:           &started,
			LastAccessed:      &lastAccessed,
			IPAddress:         "203.0.113.9",
			DeviceName:        "Firefox 131",
			DeviceType:        "Desktop",
			DeviceOS:          "Linux",
			UserAgent:         "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
		},
		IsCurrent:         true,
		ClientIdentifiers: []string{"admin-console", "billing"},
		Clients: []api.SessionClientResponse{
			{ClientIdentifier: "admin-console", Name: "Admin console"},
			{ClientIdentifier: "billing", Name: "Billing Portal", NameUnverified: true},
		},
	}})

	require.Len(t, got, 1)
	assert.Equal(t, SessionInfo{
		UserSessionID: 41,
		IsCurrent:     true,
		Started:       &started,
		LastAccessed:  &lastAccessed,
		IPAddress:     "203.0.113.9",
		DeviceName:    "Firefox 131",
		DeviceType:    "Desktop",
		DeviceOS:      "Linux",
		UserAgent:     "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
		Clients:       []string{"admin-console", "billing"},
		ClientNames:   []ClientName{{Name: "Admin console"}, {Name: "Billing Portal", Unverified: true}},
	}, got[0])
}

// Both pages list the session of the device in use first, then the others by when each was last
// active, the most recent first, whatever order the API answered in. Two last active at once, or
// neither saying when, come newest session first, and a session that does not say comes last.
func TestSessionInfos_ThisDeviceFirstThenMostRecentlyActive(t *testing.T) {
	at := func(minute int) *time.Time {
		instant := time.Date(2026, 10, 19, 9, minute, 0, 0, time.UTC)
		return &instant
	}
	session := func(id int64, lastAccessed *time.Time, current bool) api.UserSessionDetailResponse {
		return api.UserSessionDetailResponse{
			UserSessionResponse: api.UserSessionResponse{ID: id, LastAccessed: lastAccessed},
			IsCurrent:           current,
		}
	}

	got := SessionInfos([]api.UserSessionDetailResponse{
		session(3, at(50), false),
		session(9, nil, false),
		session(4, at(10), true),
		session(7, at(20), false),
		session(5, at(20), false),
		session(8, nil, false),
	})

	ids := make([]int64, 0, len(got))
	for _, s := range got {
		ids = append(ids, s.UserSessionID)
	}
	assert.Equal(t, []int64{4, 3, 7, 5, 9, 8}, ids)
}

// A user with no session gets an empty table rather than a nil the bind would carry as nothing.
func TestSessionInfos_NoSessionsIsAnEmptyList(t *testing.T) {
	got := SessionInfos(nil)
	require.NotNil(t, got)
	assert.Empty(t, got)
}

// The account Applications page renders one row per connected client, in the API's order: a
// client with a consent carries the consent's scopes and date beside the scopes its live grants
// hold, and a client with none carries no consent at all, rather than an empty one (#135
// decision 7).
func TestConnectedClientInfos_CarriesEveryFieldTheRowRendersInTheAPIsOrder(t *testing.T) {
	grantedAt := time.Date(2026, 8, 2, 10, 30, 0, 0, time.UTC)

	got := ConnectedClientInfos([]api.ConnectedClientResponse{
		{
			ClientID:          100,
			ClientIdentifier:  "billing",
			ClientName:        "Billing",
			ClientDescription: "The billing app",
			Consent:           &api.ConnectedClientConsentResponse{ID: 9, Scope: "openid profile", GrantedAt: &grantedAt},
			GrantScope:        "openid profile email",
		},
		{ClientID: 7, ClientIdentifier: "dcr_a3f9", ClientName: "Reports", ClientNameUnverified: true, GrantScope: "openid"},
		// A consent that recorded no time is still a consent.
		{ClientID: 3, ClientIdentifier: "admin-console", ClientName: "Admin console", IsCurrent: true,
			Consent: &api.ConnectedClientConsentResponse{ID: 2, Scope: "openid"}},
	})

	assert.Equal(t, []ConnectedClientInfo{
		{ClientID: 100, Client: "billing", ClientName: "Billing", ClientDescription: "The billing app",
			HasConsent: true, ConsentScope: "openid profile", GrantedAt: &grantedAt, GrantScope: "openid profile email"},
		{ClientID: 7, Client: "dcr_a3f9", ClientName: "Reports", ClientNameUnverified: true, GrantScope: "openid"},
		{ClientID: 3, Client: "admin-console", ClientName: "Admin console", HasConsent: true, ConsentScope: "openid",
			IsCurrent: true},
	}, got)
}

func TestConnectedClientInfos_NoClientsIsAnEmptyList(t *testing.T) {
	got := ConnectedClientInfos(nil)
	require.NotNil(t, got)
	assert.Empty(t, got)
}
