package handlers

import (
	"testing"

	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
)

func TestGetClientDisplayInfo(t *testing.T) {
	t.Run("ShowDisplayName true with DisplayName set - should use DisplayName", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "my-client",
			DisplayName:      "My Awesome App",
			ShowDisplayName:  true,
		}

		info := getClientDisplayInfo(database, client)

		assert.True(t, info.ShowSection)
		assert.Equal(t, "My Awesome App", info.ClientName)
		assert.False(t, info.HasLogo)
		assert.Empty(t, info.LogoURL)
		assert.Empty(t, info.Description)
		assert.Empty(t, info.WebsiteURL)

		database.AssertExpectations(t)
	})

	t.Run("ShowDisplayName true but DisplayName empty - should fallback to ClientIdentifier", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "my-client",
			DisplayName:      "",
			ShowDisplayName:  true,
		}

		info := getClientDisplayInfo(database, client)

		assert.True(t, info.ShowSection)
		assert.Equal(t, "my-client", info.ClientName)
		assert.False(t, info.HasLogo)
		assert.Empty(t, info.LogoURL)
		assert.Empty(t, info.Description)
		assert.Empty(t, info.WebsiteURL)

		database.AssertExpectations(t)
	})

	t.Run("ShowDisplayName false - should fallback to ClientIdentifier", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "my-client",
			DisplayName:      "My Awesome App",
			ShowDisplayName:  false,
		}

		info := getClientDisplayInfo(database, client)

		assert.True(t, info.ShowSection)
		assert.Equal(t, "my-client", info.ClientName)
		assert.False(t, info.HasLogo)
		assert.Empty(t, info.LogoURL)
		assert.Empty(t, info.Description)
		assert.Empty(t, info.WebsiteURL)

		database.AssertExpectations(t)
	})

	t.Run("ShowLogo true and client has logo - should set HasLogo and LogoURL", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "my-client",
			ShowLogo:         true,
		}

		database.On("ClientHasLogo", mock.Anything, int64(1)).Return(true, nil)

		info := getClientDisplayInfo(database, client)

		assert.True(t, info.ShowSection)
		assert.Equal(t, "my-client", info.ClientName)
		assert.True(t, info.HasLogo)
		assert.Equal(t, "/client/logo/my-client", info.LogoURL)
		assert.Empty(t, info.Description)
		assert.Empty(t, info.WebsiteURL)

		database.AssertExpectations(t)
	})

	t.Run("ShowLogo true but client does not have logo - should not set HasLogo", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "my-client",
			ShowLogo:         true,
		}

		database.On("ClientHasLogo", mock.Anything, int64(1)).Return(false, nil)

		info := getClientDisplayInfo(database, client)

		assert.True(t, info.ShowSection)
		assert.Equal(t, "my-client", info.ClientName)
		assert.False(t, info.HasLogo)
		assert.Empty(t, info.LogoURL)
		assert.Empty(t, info.Description)
		assert.Empty(t, info.WebsiteURL)

		database.AssertExpectations(t)
	})

	t.Run("ShowLogo false - should not call ClientHasLogo", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "my-client",
			ShowLogo:         false,
		}

		info := getClientDisplayInfo(database, client)

		assert.True(t, info.ShowSection)
		assert.Equal(t, "my-client", info.ClientName)
		assert.False(t, info.HasLogo)
		assert.Empty(t, info.LogoURL)
		assert.Empty(t, info.Description)
		assert.Empty(t, info.WebsiteURL)

		database.AssertExpectations(t)
	})

	t.Run("ShowDescription true with Description set - should include Description", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "my-client",
			Description:      "This is a great app",
			ShowDescription:  true,
		}

		info := getClientDisplayInfo(database, client)

		assert.True(t, info.ShowSection)
		assert.Equal(t, "my-client", info.ClientName)
		assert.False(t, info.HasLogo)
		assert.Empty(t, info.LogoURL)
		assert.Equal(t, "This is a great app", info.Description)
		assert.Empty(t, info.WebsiteURL)

		database.AssertExpectations(t)
	})

	t.Run("ShowDescription true but Description empty - should not include Description", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "my-client",
			Description:      "",
			ShowDescription:  true,
		}

		info := getClientDisplayInfo(database, client)

		assert.True(t, info.ShowSection)
		assert.Equal(t, "my-client", info.ClientName)
		assert.False(t, info.HasLogo)
		assert.Empty(t, info.LogoURL)
		assert.Empty(t, info.Description)
		assert.Empty(t, info.WebsiteURL)

		database.AssertExpectations(t)
	})

	t.Run("ShowDescription false - should not include Description", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "my-client",
			Description:      "This is a great app",
			ShowDescription:  false,
		}

		info := getClientDisplayInfo(database, client)

		assert.True(t, info.ShowSection)
		assert.Equal(t, "my-client", info.ClientName)
		assert.False(t, info.HasLogo)
		assert.Empty(t, info.LogoURL)
		assert.Empty(t, info.Description)
		assert.Empty(t, info.WebsiteURL)

		database.AssertExpectations(t)
	})

	t.Run("ShowWebsiteURL true with WebsiteURL set - should include WebsiteURL", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "my-client",
			WebsiteURL:       "https://example.com",
			ShowWebsiteURL:   true,
		}

		info := getClientDisplayInfo(database, client)

		assert.True(t, info.ShowSection)
		assert.Equal(t, "my-client", info.ClientName)
		assert.False(t, info.HasLogo)
		assert.Empty(t, info.LogoURL)
		assert.Empty(t, info.Description)
		assert.Equal(t, "https://example.com", info.WebsiteURL)

		database.AssertExpectations(t)
	})

	t.Run("ShowWebsiteURL true but WebsiteURL empty - should not include WebsiteURL", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "my-client",
			WebsiteURL:       "",
			ShowWebsiteURL:   true,
		}

		info := getClientDisplayInfo(database, client)

		assert.True(t, info.ShowSection)
		assert.Equal(t, "my-client", info.ClientName)
		assert.False(t, info.HasLogo)
		assert.Empty(t, info.LogoURL)
		assert.Empty(t, info.Description)
		assert.Empty(t, info.WebsiteURL)

		database.AssertExpectations(t)
	})

	t.Run("ShowWebsiteURL false - should not include WebsiteURL", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "my-client",
			WebsiteURL:       "https://example.com",
			ShowWebsiteURL:   false,
		}

		info := getClientDisplayInfo(database, client)

		assert.True(t, info.ShowSection)
		assert.Equal(t, "my-client", info.ClientName)
		assert.False(t, info.HasLogo)
		assert.Empty(t, info.LogoURL)
		assert.Empty(t, info.Description)
		assert.Empty(t, info.WebsiteURL)

		database.AssertExpectations(t)
	})

	t.Run("All fields enabled and populated - should include all", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "my-client",
			DisplayName:      "My Awesome App",
			Description:      "This is a great app",
			WebsiteURL:       "https://example.com",
			ShowLogo:         true,
			ShowDisplayName:  true,
			ShowDescription:  true,
			ShowWebsiteURL:   true,
		}

		database.On("ClientHasLogo", mock.Anything, int64(1)).Return(true, nil)

		info := getClientDisplayInfo(database, client)

		assert.True(t, info.ShowSection)
		assert.Equal(t, "My Awesome App", info.ClientName)
		assert.True(t, info.HasLogo)
		assert.Equal(t, "/client/logo/my-client", info.LogoURL)
		assert.Equal(t, "This is a great app", info.Description)
		assert.Equal(t, "https://example.com", info.WebsiteURL)

		database.AssertExpectations(t)
	})

	t.Run("All fields disabled - should still show ClientIdentifier", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "my-client",
			DisplayName:      "My Awesome App",
			Description:      "This is a great app",
			WebsiteURL:       "https://example.com",
			ShowLogo:         false,
			ShowDisplayName:  false,
			ShowDescription:  false,
			ShowWebsiteURL:   false,
		}

		info := getClientDisplayInfo(database, client)

		assert.True(t, info.ShowSection)
		assert.Equal(t, "my-client", info.ClientName)
		assert.False(t, info.HasLogo)
		assert.Empty(t, info.LogoURL)
		assert.Empty(t, info.Description)
		assert.Empty(t, info.WebsiteURL)

		database.AssertExpectations(t)
	})

	t.Run("CreatedViaDCR with a Description - getClientDisplayInfo is unaffected by the column", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "dcr_a3f9e1b2",
			Description:      "Payroll Portal",
			CreatedViaDCR:    true,
		}

		info := getClientDisplayInfo(database, client)

		// The password and OTP screens read this function and must keep showing the identifier,
		// so the unverified marking is confined to the consent screen (#108).
		assert.Equal(t, "dcr_a3f9e1b2", info.ClientName)
		assert.Empty(t, info.Description)

		database.AssertExpectations(t)
	})

	t.Run("ClientHasLogo returns error - should default to false and log warning", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "my-client",
			ShowLogo:         true,
		}

		database.On("ClientHasLogo", mock.Anything, int64(1)).Return(false, assert.AnError)

		info := getClientDisplayInfo(database, client)

		assert.True(t, info.ShowSection)
		assert.Equal(t, "my-client", info.ClientName)
		assert.False(t, info.HasLogo)
		assert.Empty(t, info.LogoURL)
		assert.Empty(t, info.Description)
		assert.Empty(t, info.WebsiteURL)

		database.AssertExpectations(t)
	})
}

// TestConsentClientName owns the whole precedence rule for the name the consent screen shows.
// Every case varies exactly one field from the base case below, so a case that fails names the
// field that broke it.
//
// The base case is a self-registered client carrying the name it asserted at registration, which
// is the situation the rule exists for: the client picked that string itself, so it is shown as a
// claim rather than as something this server vouched for (#108).
func TestConsentClientName(t *testing.T) {
	base := func() *models.Client {
		return &models.Client{
			ClientIdentifier: "dcr_a3f9e1b2",
			Description:      "Payroll Portal",
			CreatedViaDCR:    true,
		}
	}

	tests := []struct {
		name           string
		mutate         func(c *models.Client)
		wantName       string
		wantUnverified bool
		why            string
	}{
		{
			name:           "self-registered with a self-asserted name",
			mutate:         func(c *models.Client) {},
			wantName:       "Payroll Portal",
			wantUnverified: true,
			why:            "the base case: the client named itself, so the name is a claim",
		},
		{
			name:           "self-registered with no name asserted",
			mutate:         func(c *models.Client) { c.Description = "" },
			wantName:       "dcr_a3f9e1b2",
			wantUnverified: false,
			why: "there is nothing attacker-supplied on the page, so there is nothing to mark " +
				"as unverified",
		},
		{
			name:           "a description on a client that did not register itself",
			mutate:         func(c *models.Client) { c.CreatedViaDCR = false },
			wantName:       "dcr_a3f9e1b2",
			wantUnverified: false,
			why: "keep this: it fails if the marking is driven by Description rather than by the " +
				"column, which is the whole reason the column exists. An administrator can name a " +
				"client dcr_anything, so the identifier is not a substitute",
		},
		{
			name: "an administrator display name on a self-registered client",
			mutate: func(c *models.Client) {
				c.ShowDisplayName = true
				c.DisplayName = "Acme Payroll"
			},
			wantName:       "Acme Payroll",
			wantUnverified: false,
			why: "a human reviewed the client and named it, so the name is no longer self-asserted " +
				"and the notice drops with it",
		},
		{
			name: "display name enabled but empty on a self-registered client",
			mutate: func(c *models.Client) {
				c.ShowDisplayName = true
				c.DisplayName = ""
			},
			wantName:       "Payroll Portal",
			wantUnverified: true,
			why:            "an empty display name does not consume the precedence",
		},
		{
			name: "a display name that is not shown on a self-registered client",
			mutate: func(c *models.Client) {
				c.ShowDisplayName = false
				c.DisplayName = "Acme Payroll"
			},
			wantName:       "Payroll Portal",
			wantUnverified: true,
			why:            "the visibility toggle gates the administrator's name, not the field alone",
		},
		{
			name: "show description enabled on a self-registered client",
			mutate: func(c *models.Client) {
				c.ShowDescription = true
			},
			wantName:       "Payroll Portal",
			wantUnverified: true,
			why: "the consent name does not read ShowDescription. HandleConsentGet suppresses the " +
				"separate description line instead, so the same string is not printed twice",
		},
		{
			name: "an ordinary client with nothing configured",
			mutate: func(c *models.Client) {
				c.CreatedViaDCR = false
				c.Description = ""
				c.ClientIdentifier = "my-client"
			},
			wantName:       "my-client",
			wantUnverified: false,
			why:            "today's behaviour, unchanged, and nothing on the page to warn about",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := base()
			tt.mutate(client)

			name, unverified := consentClientName(client)

			assert.Equal(t, tt.wantName, name, tt.why)
			assert.Equal(t, tt.wantUnverified, unverified, tt.why)
		})
	}
}
