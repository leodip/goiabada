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
			Id:                41,
			SessionIdentifier: "sid-41",
			Started:           &started,
			LastAccessed:      &lastAccessed,
			IpAddress:         "203.0.113.9",
			DeviceName:        "Firefox 131",
			DeviceType:        "Desktop",
			DeviceOS:          "Linux",
			UserAgent:         "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
		},
		IsCurrent:         true,
		ClientIdentifiers: []string{"admin-console", "billing"},
	}})

	require.Len(t, got, 1)
	assert.Equal(t, SessionInfo{
		UserSessionId: 41,
		IsCurrent:     true,
		Started:       &started,
		LastAccessed:  &lastAccessed,
		IpAddress:     "203.0.113.9",
		DeviceName:    "Firefox 131",
		DeviceType:    "Desktop",
		DeviceOS:      "Linux",
		UserAgent:     "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
		Clients:       []string{"admin-console", "billing"},
	}, got[0])
}

// Both pages list the newest session first, by id, whatever order the API answered in.
func TestSessionInfos_NewestIdFirst(t *testing.T) {
	got := SessionInfos([]api.UserSessionDetailResponse{
		{UserSessionResponse: api.UserSessionResponse{Id: 3}},
		{UserSessionResponse: api.UserSessionResponse{Id: 7}},
		{UserSessionResponse: api.UserSessionResponse{Id: 5}},
	})

	ids := make([]int64, 0, len(got))
	for _, s := range got {
		ids = append(ids, s.UserSessionId)
	}
	assert.Equal(t, []int64{7, 5, 3}, ids)
}

// A user with no session gets an empty table rather than a nil the bind would carry as nothing.
func TestSessionInfos_NoSessionsIsAnEmptyList(t *testing.T) {
	got := SessionInfos(nil)
	require.NotNil(t, got)
	assert.Empty(t, got)
}

// The account consents page and the admin user consents page render the same row. The order is
// the API's: neither page has ever sorted it.
func TestConsentInfos_CarriesEveryFieldTheRowRendersInTheAPIsOrder(t *testing.T) {
	grantedAt := time.Date(2026, 8, 2, 10, 30, 0, 0, time.UTC)

	got := ConsentInfos([]api.UserConsentResponse{
		{
			Id:                9,
			ClientId:          100,
			UserId:            4,
			Scope:             "openid profile",
			GrantedAt:         &grantedAt,
			ClientIdentifier:  "billing",
			ClientDescription: "The billing app",
		},
		// grantedAt is nullable on the wire: the row is shown undated rather than dropped.
		{Id: 2, Scope: "openid", ClientIdentifier: "reports"},
	})

	assert.Equal(t, []ConsentInfo{
		{ConsentId: 9, Client: "billing", ClientDescription: "The billing app", GrantedAt: &grantedAt, Scope: "openid profile"},
		{ConsentId: 2, Client: "reports", Scope: "openid"},
	}, got)
}

func TestConsentInfos_NoConsentsIsAnEmptyList(t *testing.T) {
	got := ConsentInfos(nil)
	require.NotNil(t, got)
	assert.Empty(t, got)
}
