package handlers

import (
	"fmt"
	"log/slog"

	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
)

// ClientDisplayInfo contains the client information to display on auth and consent screens
type ClientDisplayInfo struct {
	ShowSection bool   // true if any display info is available
	ClientName  string // DisplayName if enabled+set, else ClientIdentifier
	HasLogo     bool
	LogoURL     string
	Description string // empty if not to be shown
	WebsiteURL  string // empty if not to be shown
}

// getClientDisplayInfo computes what client information should be displayed based on the client's display settings
func getClientDisplayInfo(database data.Database, client *models.Client) *ClientDisplayInfo {
	info := &ClientDisplayInfo{}

	if client.ShowDisplayName && client.DisplayName != "" {
		info.ClientName = client.DisplayName
	} else {
		info.ClientName = client.ClientIdentifier
	}

	if client.ShowLogo {
		hasLogo, err := database.ClientHasLogo(nil, client.Id)
		if err != nil {
			slog.Warn(fmt.Sprintf("failed to check if client has logo, defaulting to false: %v", err))
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

// consentClientName returns the name the consent screen shows for a client, and whether that name
// is the client's own claim about itself rather than something an administrator vouched for.
// RFC 7591 section 5 requires all client metadata be treated as self-asserted, so a name a client
// chose for itself is shown as a claim, never as an attestation (#108).
//
// The precedence is about the provenance of the NAME, not about how trustworthy the client is: an
// administrator who reviewed a self-registered client and gave it a display name has vouched for
// that name, so the marking drops with it. The client itself cannot reach either of the first two
// rungs, because it cannot set DisplayName and cannot clear created_via_dcr.
//
// Consent only. getClientDisplayInfo is deliberately left alone, so the password and OTP screens
// keep showing the identifier: a warning repeated on three screens stops being read, and consent is
// the one screen where the user grants authority.
func consentClientName(client *models.Client) (name string, unverified bool) {
	if client.ShowDisplayName && client.DisplayName != "" {
		return client.DisplayName, false // an administrator named it
	}
	if client.CreatedViaDCR && client.Description != "" {
		return client.Description, true // the client named itself
	}
	return client.ClientIdentifier, false
}
