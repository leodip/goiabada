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
	ClientName  string // DisplayName if enabled+set, else empty
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
