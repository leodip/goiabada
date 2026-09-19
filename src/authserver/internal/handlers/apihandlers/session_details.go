package apihandlers

import (
	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/models"
)

// buildSessionDetails is the one loop behind all three session list endpoints: filter to the
// sessions still active under the current settings, hydrate the clients they authorized, and map
// each survivor.
//
// It exists because the three producers each carried their own copy of it, which is how one of
// them came to set isCurrent while the other two published a constant false. Sharing it means the
// next divergence has nowhere to happen: every endpoint's rows are built by this function calling
// one mapper (#373).
//
// sessions must already have their Clients loaded, through UserSessionsLoadClients; this fills in
// each UserSessionClient's Client. currentSid is the caller's own session identifier, empty when
// the access token carries no sid claim.
func buildSessionDetails(
	database data.Database,
	sessions []models.UserSession,
	settings *models.Settings,
	currentSid string,
) ([]api.UserSessionDetailResponse, error) {

	valid := make([]models.UserSession, 0, len(sessions))
	for _, session := range sessions {
		// Invalid sessions are omitted rather than reported: the endpoints list what is live,
		// and the background worker deletes the rest within its sweep interval (#373 decision 2).
		if !session.IsValid(settings.UserSessionIdleTimeoutInSeconds, settings.UserSessionMaxLifetimeInSeconds, nil) {
			continue
		}
		valid = append(valid, session)
	}

	// One GetClientsByIds over the union of client ids across the whole page, in place of the
	// per-session UserSessionClientsLoadClients the three loops used to call: at 50 sessions that
	// was 50 queries to name the handful of clients a deployment has (#373 decision 9).
	if err := loadSessionClients(database, valid); err != nil {
		return nil, err
	}

	details := make([]api.UserSessionDetailResponse, 0, len(valid))
	for i := range valid {
		detail := apimapping.ToUserSessionDetailResponse(&valid[i], currentSid)
		if detail == nil {
			continue
		}
		details = append(details, *detail)
	}

	return details, nil
}

// loadSessionClients fills in the Client on every UserSessionClient of every session given, in
// one lookup. It is UserSessionClientsLoadClients hoisted out of the per-session loop, and it
// keeps that method's refusal of an id with no row: a session naming a client that does not
// exist is a broken row rather than a session with one fewer client, and answering 200 with the
// client silently missing would hide it.
//
// The union it hands over is bounded by the deployment's client count and by nothing else, so
// GetClientsByIds is the one that decides how many ids a single statement may bind; an id list
// longer than that is read in several statements there rather than refused by the engine (#373).
func loadSessionClients(database data.Database, sessions []models.UserSession) error {
	clientIds := make([]int64, 0)
	seen := make(map[int64]bool)
	for _, session := range sessions {
		for _, usc := range session.Clients {
			if !seen[usc.ClientId] {
				seen[usc.ClientId] = true
				clientIds = append(clientIds, usc.ClientId)
			}
		}
	}
	if len(clientIds) == 0 {
		return nil
	}

	clients, err := database.GetClientsByIds(nil, clientIds)
	if err != nil {
		return errs.Wrap(err, "unable to get clients by ids")
	}

	clientsById := make(map[int64]models.Client, len(clients))
	for _, client := range clients {
		clientsById[client.Id] = client
	}

	for _, session := range sessions {
		for i, usc := range session.Clients {
			client, ok := clientsById[usc.ClientId]
			if !ok {
				return errs.Errorf("client with id %d not found", usc.ClientId)
			}
			session.Clients[i].Client = client
		}
	}

	return nil
}
