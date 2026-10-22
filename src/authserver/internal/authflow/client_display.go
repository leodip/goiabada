package authflow

import (
	"context"
	"database/sql"
	"log/slog"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// ClientDisplayInfo is the client block the password, OTP and consent screens show: what of the
// client an administrator chose to display.
type ClientDisplayInfo struct {
	ShowSection bool   // true if any display info is available
	ClientName  string // DisplayName if enabled+set, else ClientIdentifier
	HasLogo     bool
	LogoURL     string
	Description string // empty if not to be shown
	WebsiteURL  string // empty if not to be shown
}

// clientDisplayDatabase is the read getClientDisplayInfo makes: whether the client has a logo to
// show. data.Database satisfies it.
type clientDisplayDatabase interface {
	ClientHasLogo(ctx context.Context, tx *sql.Tx, clientId int64) (bool, error)
}

// ceremonyClientDisplayDatabase is what loadClientDisplay reads: the ceremony's client, and whether
// it has a logo to show. data.Database satisfies it.
type ceremonyClientDisplayDatabase interface {
	clientDisplayDatabase

	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*record.Client, error)
}

// loadClientDisplay loads the ceremony's client and returns its block (getClientDisplayInfo), for a
// form the step is about to render. A failed read, or a client not found, is returned as an error.
// A step loads it only when it renders a form: a submission that is accepted redirects, and has no
// form to show it in.
func loadClientDisplay(ctx context.Context, database ceremonyClientDisplayDatabase,
	authContext *ceremony.AuthContext) (*ClientDisplayInfo, error) {

	client, err := database.GetClientByClientIdentifier(ctx, nil, authContext.ClientId)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errs.New("client not found")
	}
	return getClientDisplayInfo(ctx, database, client), nil
}

// getClientDisplayInfo is the client block for client, from its display settings. The logo is read
// only when the client shows one, and a failed read shows none, with a warn record: the block is
// decoration, and a sign-in does not fail over it.
func getClientDisplayInfo(ctx context.Context, database clientDisplayDatabase, client *record.Client) *ClientDisplayInfo {
	info := &ClientDisplayInfo{}

	if client.ShowDisplayName && client.DisplayName != "" {
		info.ClientName = client.DisplayName
	} else {
		info.ClientName = client.ClientIdentifier
	}

	if client.ShowLogo {
		hasLogo, err := database.ClientHasLogo(ctx, nil, client.Id)
		if err != nil {
			slog.WarnContext(ctx, "unable to check whether the client has a logo, defaulting to false",
				"client_identifier", client.ClientIdentifier, "error", err)
		} else if hasLogo {
			info.HasLogo = true
			info.LogoURL = "/client/logo/" + client.ClientIdentifier
		}
	}

	if client.ShowDescription && client.Description != "" {
		info.Description = client.Description
	}

	if client.ShowWebsiteURL && client.WebsiteURL != "" {
		info.WebsiteURL = client.WebsiteURL
	}

	info.ShowSection = info.ClientName != "" || info.HasLogo || info.Description != "" || info.WebsiteURL != ""

	return info
}
