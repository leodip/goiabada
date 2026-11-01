package integration

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/handlers/apihandlers"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A profile save that leaves the optional pageLanguage out leaves the stored page language
// untouched, even when a choice was saved after the save read the user (#631 decision 8). The
// database below is the real one for every read and write; it only orders the two saves: as the
// first save reads its user, a second save commits German, and the first then writes its other
// profile fields from what it read, which still says Automatic.

// choiceSavedDuringTheRead is the real database, but the first read of the user by subject or by id
// commits a page language of de through the profile's own write before it answers with the row as
// it was.
type choiceSavedDuringTheRead struct {
	data.Database
	t     *testing.T
	saved bool
}

func (d *choiceSavedDuringTheRead) saveChoiceUnder(ctx context.Context, read *record.User) {
	if d.saved || read == nil {
		return
	}
	d.saved = true
	choice := *read
	choice.PageLanguage = "de"
	require.NoError(d.t, d.SetUserProfile(ctx, nil, &choice, true))
}

func (d *choiceSavedDuringTheRead) GetUserBySubject(ctx context.Context, tx *sql.Tx, subject string) (*record.User, error) {
	read, err := d.Database.GetUserBySubject(ctx, tx, subject)
	require.NoError(d.t, err)
	d.saveChoiceUnder(ctx, read)
	return read, nil
}

func (d *choiceSavedDuringTheRead) GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*record.User, error) {
	read, err := d.Database.GetUserById(ctx, tx, userId)
	require.NoError(d.t, err)
	d.saveChoiceUnder(ctx, read)
	return read, nil
}

type discardAudit struct{}

func (discardAudit) Log(context.Context, string, map[string]interface{}) {}

func TestPageLanguage_AProfileSaveLeavingItOutCannotUndoAChoiceSavedMeanwhile(t *testing.T) {
	routes := []struct {
		name  string
		serve func(t *testing.T, db *choiceSavedDuringTheRead, user *record.User, body string) *httptest.ResponseRecorder
	}{
		{"PUT /api/v1/account/profile", func(t *testing.T, db *choiceSavedDuringTheRead, user *record.User, body string) *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodPut, "/api/v1/account/profile", strings.NewReader(body))
			req = req.WithContext(reqctx.WithValidatedToken(req.Context(),
				oauth.JwtToken{Claims: map[string]interface{}{"sub": user.Subject}}))
			rr := httptest.NewRecorder()
			apihandlers.HandleAccountProfilePut(db, accountvalidation.NewProfileValidator(database), discardAudit{}).
				ServeHTTP(rr, req)
			return rr
		}},
		{"PUT /api/v1/admin/users/{id}/profile", func(t *testing.T, db *choiceSavedDuringTheRead, user *record.User, body string) *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/users/"+strconv.FormatInt(user.Id, 10)+"/profile",
				strings.NewReader(body))
			req.SetPathValue("id", strconv.FormatInt(user.Id, 10))
			req = req.WithContext(reqctx.WithValidatedToken(req.Context(),
				oauth.JwtToken{Claims: map[string]interface{}{"sub": "an-administrator", "scope": "authserver:manage"}}))
			rr := httptest.NewRecorder()
			apihandlers.HandleUserProfilePut(db, accountvalidation.NewProfileValidator(database), discardAudit{}).
				ServeHTTP(rr, req)
			return rr
		}},
	}
	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			user, _ := newPageLanguageUser(t, true, "", "")
			db := &choiceSavedDuringTheRead{Database: database, t: t}

			rr := route.serve(t, db, user, `{"givenName":"Ada","familyName":"Lovelace"}`)
			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			require.True(t, db.saved, "the choice was not saved during the read, so the case proves nothing")

			stored, err := database.GetUserById(context.Background(), nil, user.Id)
			require.NoError(t, err)
			assert.Equal(t, "Ada", stored.GivenName, "the save's own fields landed")
			assert.Equal(t, "de", stored.PageLanguage, "leaving pageLanguage out leaves the choice saved meanwhile")
		})
	}
}
