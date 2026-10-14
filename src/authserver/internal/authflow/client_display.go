package authflow

import (
	"context"
	"database/sql"
	"log/slog"

	"github.com/leodip/goiabada/authserver/internal/record"
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

// ConsentClientName returns the name the consent screen shows for a client, and whether that name
// is the client's own claim about itself rather than something an administrator vouched for.
// RFC 7591 section 5 requires all client metadata be treated as self-asserted, so a name a client
// chose for itself is shown as a claim, never as an attestation (#108).
//
// The precedence is about the provenance of the NAME, not about how trustworthy the client is: an
// administrator who reviewed a self-registered client and gave it a display name has vouched for
// that name, so the marking drops with it. The client itself cannot reach either of the first two
// rungs, because it cannot set DisplayName and cannot clear created_via_dcr.
//
// Consent, and the redirect-blocked page that names the same client, only. getClientDisplayInfo
// keeps the identifier, so the password and OTP screens show it: a warning repeated on three screens
// stops being read, and consent is the one screen where the user grants authority.
func ConsentClientName(client *record.Client) (name string, unverified bool) {
	if client.ShowDisplayName && client.DisplayName != "" {
		return client.DisplayName, false // an administrator named it
	}
	if client.CreatedViaDCR && client.Description != "" {
		return client.Description, true // the client named itself
	}
	return client.ClientIdentifier, false
}
