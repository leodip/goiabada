package handlers

import (
	"net/http"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Seam 4 for the two answers a rotation's family record adds to the refresh responder (#132, #259,
// #437): a containment that recorded the family is audited even when it revoked no live row, and a
// family recorded revoked after the validator's read is refused like a lost claim. What makes them
// happen is the issuer's, pinned in issuance; this pins what the endpoint does with each.

// A replay whose containment revoked nothing but wrote the family's record is audited. A rotation in
// flight holds no live row to revoke, so the containment that arrives between its claim and its
// insert changes no row, yet it contained the family and its event is the only trace of the theft it
// answered (#132). The payload carries the zero count.
func TestHandleTokenPost_Refresh_Replay_ARecordWrittenWithNothingLiveIsAudited(t *testing.T) {
	for _, tc := range []struct {
		name     string
		grant    bool
		wantFlow string
	}{
		{"authorization code family", false, "auth_code"},
		{"ROPC family", true, "ropc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := newTokenEndpoint(t)
			if tc.grant {
				endpoint.validates(ropcRefreshGrant(true))
			} else {
				endpoint.validates(codeRefreshGrant(true))
			}

			endpoint.issuer.On("IssueRefreshTokenGrant", mock.Anything, mock.Anything, mock.Anything).
				Return(nil, nil, &issuance.RefreshTokenReplayedError{FamilyRevokedCount: 0, FamilyRecorded: true}).Once()

			var logged []map[string]interface{}
			endpoint.auditLogger.On("Log", mock.Anything, audit.EventRefreshTokenReplayDetected, mock.AnythingOfType("map[string]interface {}")).
				Run(func(args mock.Arguments) {
					logged = append(logged, args.Get(2).(map[string]interface{}))
				}).Return()
			endpoint.jsonWriter.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
				detail, ok := err.(*oauth.ErrorDetail)
				return ok && detail.Code() == "invalid_grant" &&
					detail.Description() == "This refresh token has been revoked."
			})).Return().Once()

			endpoint.post(t, "grant_type=refresh_token&refresh_token=replayed")

			endpoint.assertExpectations(t)
			require.Len(t, logged, 1, "the record alone is worth one replay event")
			assert.Equal(t, int64(0), logged[0]["revokedCount"])
			assert.Equal(t, tc.wantFlow, logged[0]["flow"])
		})
	}
}

// A family recorded revoked between the validator's read and the rotation's transaction is refused
// with the lost claim's answer and audited as nothing: nothing was claimed, minted or contained by
// this request, and the record says nothing a client can act on (#132, #259).
func TestHandleTokenPost_Refresh_AFamilyRevokedInTheGapIsRefusedAsARevokedToken(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input bool
	}{
		{"authorization code token", false},
		{"ROPC token", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := newTokenEndpoint(t)
			if tc.input {
				endpoint.validates(ropcRefreshGrant(false))
			} else {
				endpoint.validates(codeRefreshGrant(false))
			}

			endpoint.issuer.On("IssueRefreshTokenGrant", mock.Anything, mock.Anything, mock.Anything).
				Return(nil, nil, issuance.ErrRefreshFamilyRevoked).Once()
			endpoint.jsonWriter.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
				detail, ok := err.(*oauth.ErrorDetail)
				return ok && detail.Code() == "invalid_grant" &&
					detail.Description() == "This refresh token has been revoked." &&
					detail.HTTPStatus() == http.StatusBadRequest
			})).Return().Once()

			endpoint.post(t, "grant_type=refresh_token&refresh_token=presented")

			endpoint.assertExpectations(t)
			endpoint.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}
