package backchannel

import (
	"context"
	"database/sql"

	"github.com/leodip/goiabada/authserver/internal/record"
)

// Delivery is one logout token to one app: the client it goes to, as the end that collected it read
// the client, and the user and session it is about.
type Delivery struct {
	// ClientId and ClientIdentifier name the client; the token's aud is the identifier.
	ClientId         int64
	ClientIdentifier string
	// URI is the client's back-channel logout URI, and IsPublic and CreatedViaDCR are what #784
	// decision 6's rule is checked against again before the token is sent: http only for an
	// administrator's confidential client. CreatedViaDCR also chooses the job's class.
	URI           string
	IsPublic      bool
	CreatedViaDCR bool
	// UserId is the user the token is about, recorded on the audit event, and Subject its sub.
	UserId  int64
	Subject string
	// SessionIdentifier is the token's sid, the session that ended, or empty for a token about every
	// session of the user, which carries sub alone (#784 decision 3).
	SessionIdentifier string
}

// SessionDatabase is what SessionDeliveries reads: the apps a session served, with their clients, as
// last committed.
type SessionDatabase interface {
	GetCommittedUserSessionClients(ctx context.Context, tx *sql.Tx, userSessionId int64) ([]record.UserSessionClient, error)
}

// SessionDeliveries is the logout tokens the end of session sends: one to each app the session
// served that registered a back-channel logout URI, naming subject, the session's user's, and the
// session (#784 decision 3). An app with no URI is sent nothing.
//
// The caller reads it on the end's own transaction, holding the session's row and before the
// session's deletion takes its apps with it, so an app a ceremony adds to the session at the same
// moment is either here or refused. The apps are read as last committed, since on MySQL an ordinary
// read would answer the transaction's snapshot from before the row was taken. It answers nil when
// there is nobody to tell.
func SessionDeliveries(ctx context.Context, db SessionDatabase, tx *sql.Tx, session *record.UserSession,
	subject string) ([]Delivery, error) {

	sessionClients, err := db.GetCommittedUserSessionClients(ctx, tx, session.Id)
	if err != nil {
		return nil, err
	}

	var deliveries []Delivery
	for _, sessionClient := range sessionClients {
		if delivery, tells := SessionClientDelivery(&sessionClient.Client, session, subject); tells {
			deliveries = append(deliveries, delivery)
		}
	}
	return deliveries, nil
}

// SessionClientDelivery is the logout token the end of client's part of session sends to client,
// naming subject, the session's user's, and the session (#784 decisions 2 and 3), and false when the
// client registered no back-channel logout URI, so it is sent nothing.
func SessionClientDelivery(client *record.Client, session *record.UserSession, subject string) (Delivery, bool) {
	if client.BackchannelLogoutURI == "" {
		return Delivery{}, false
	}
	return Delivery{
		ClientId:          client.Id,
		ClientIdentifier:  client.ClientIdentifier,
		URI:               client.BackchannelLogoutURI,
		IsPublic:          client.IsPublic,
		CreatedViaDCR:     client.CreatedViaDCR,
		UserId:            session.UserId,
		Subject:           subject,
		SessionIdentifier: session.SessionIdentifier,
	}, true
}
