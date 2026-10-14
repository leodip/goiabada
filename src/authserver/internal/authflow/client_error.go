package authflow

import (
	"context"
	"database/sql"
	"log/slog"

	"github.com/leodip/goiabada/authserver/internal/record"
)

// ClientError is an authorization error response an operation owes the client: what to say, and
// which client is answered. Where and how it is said, the redirect URI, the response mode and type,
// and the state, are the ceremony's, which the handler holds. The handler writes it through the
// client-error responder, whose gates still decide whether it may leave this server.
type ClientError struct {
	// Client is the client answered, or nil when its provenance could not be resolved. Nil is the
	// untrusted case: the responder then withholds the redirect (#108).
	Client      *record.Client
	Code        string
	Description string
}

// clientReader is the read ClientProvenance makes. *data.Database satisfies it.
type clientReader interface {
	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*record.Client, error)
}

// ClientProvenance loads the client behind a ceremony for the trust decision of an error response,
// where a step reaches one without having loaded the client.
//
// It answers nil instead of an error. The step is already on its way to answering the client with
// an error, so a lookup that fails must not turn that refusal into a 500; and unresolved provenance
// is the untrusted case, which withholds the redirect rather than performing it (#108).
func ClientProvenance(ctx context.Context, database clientReader, clientIdentifier string) *record.Client {
	client, err := database.GetClientByClientIdentifier(ctx, nil, clientIdentifier)
	if err != nil {
		slog.ErrorContext(ctx, "unable to load the client while answering it with an error, treating its provenance as unresolved",
			"client_identifier", clientIdentifier, "error", err)
		return nil
	}
	return client
}
