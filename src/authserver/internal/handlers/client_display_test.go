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

	t.Run("ShowDisplayName true but DisplayName empty - should have empty ClientName", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "my-client",
			DisplayName:      "",
			ShowDisplayName:  true,
		}

		info := getClientDisplayInfo(database, client)

		assert.False(t, info.ShowSection)
		assert.Empty(t, info.ClientName)
		assert.False(t, info.HasLogo)
		assert.Empty(t, info.LogoURL)
		assert.Empty(t, info.Description)
		assert.Empty(t, info.WebsiteURL)

		database.AssertExpectations(t)
	})

	t.Run("ShowDisplayName false - should have empty ClientName", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "my-client",
			DisplayName:      "My Awesome App",
			ShowDisplayName:  false,
		}

		info := getClientDisplayInfo(database, client)

		assert.False(t, info.ShowSection)
		assert.Empty(t, info.ClientName)
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
		assert.Empty(t, info.ClientName)
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

		assert.False(t, info.ShowSection)
		assert.Empty(t, info.ClientName)
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

		assert.False(t, info.ShowSection)
		assert.Empty(t, info.ClientName)
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
		assert.Empty(t, info.ClientName)
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

		assert.False(t, info.ShowSection)
		assert.Empty(t, info.ClientName)
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

		assert.False(t, info.ShowSection)
		assert.Empty(t, info.ClientName)
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
		assert.Empty(t, info.ClientName)
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

		assert.False(t, info.ShowSection)
		assert.Empty(t, info.ClientName)
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

		assert.False(t, info.ShowSection)
		assert.Empty(t, info.ClientName)
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

	t.Run("All fields disabled - should show nothing", func(t *testing.T) {
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

		assert.False(t, info.ShowSection)
		assert.Empty(t, info.ClientName)
		assert.False(t, info.HasLogo)
		assert.Empty(t, info.LogoURL)
		assert.Empty(t, info.Description)
		assert.Empty(t, info.WebsiteURL)

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

		assert.False(t, info.ShowSection)
		assert.Empty(t, info.ClientName)
		assert.False(t, info.HasLogo)
		assert.Empty(t, info.LogoURL)
		assert.Empty(t, info.Description)
		assert.Empty(t, info.WebsiteURL)

		database.AssertExpectations(t)
	})
}
