package datav2

import (
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/spf13/viper"
)

func seed(database Database) error {

	encryptionKey := securecookie.GenerateRandomKey(32)

	clientSecret := lib.GenerateSecureRandomString(60)
	clientSecretEncrypted, _ := lib.EncryptText(clientSecret, encryptionKey)

	client1 := &entitiesv2.Client{
		ClientIdentifier:                        constants.SystemClientIdentifier,
		Description:                             "Website client (system-level)",
		Enabled:                                 true,
		ConsentRequired:                         false,
		IsPublic:                                false,
		AuthorizationCodeEnabled:                true,
		DefaultAcrLevel:                         enums.AcrLevel2,
		ClientCredentialsEnabled:                false,
		ClientSecretEncrypted:                   clientSecretEncrypted,
		IncludeOpenIDConnectClaimsInAccessToken: enums.ThreeStateSettingDefault.String(),
	}

	client1, err := database.CreateClient(nil, client1)
	if err != nil {
		return err
	}

	var redirectURI = &entitiesv2.RedirectURI{
		URI:      lib.GetBaseUrl() + "/auth/callback",
		ClientId: client1.Id,
	}
	_, err = database.CreateClientRedirectURI(nil, client1.Id, redirectURI)
	if err != nil {
		return err
	}

	adminEmail := viper.GetString("Admin.Email")
	if len(adminEmail) == 0 {
		const defaultAdminEmail = "admin@example.com"
		slog.Warn(fmt.Sprintf("Environment variable GOIABADA_ADMIN_EMAIL is not set. Will default admin email to '%v'", defaultAdminEmail))
		adminEmail = defaultAdminEmail
	}

	adminPassword := viper.GetString("Admin.Password")
	if len(adminPassword) == 0 {
		const defaultAdminPassword = "admin123"
		slog.Warn(fmt.Sprintf("Environment variable GOIABADA_ADMIN_PASSWORD is not set. Will default admin password to '%v'", defaultAdminPassword))
		adminPassword = defaultAdminPassword
	}

	passwordHash, _ := lib.HashPassword(adminPassword)

	user := &entitiesv2.User{
		Subject:       uuid.New(),
		Email:         adminEmail,
		EmailVerified: true,
		PasswordHash:  passwordHash,
		Enabled:       true,
	}
	user, err = database.CreateUser(nil, user)
	if err != nil {
		return err
	}

	resource := &entitiesv2.Resource{
		ResourceIdentifier: constants.AuthServerResourceIdentifier,
		Description:        "Authorization server (system-level)",
	}
	resource, err = database.CreateResource(nil, resource)
	if err != nil {
		return err
	}

	permission1 := &entitiesv2.Permission{
		PermissionIdentifier: constants.UserinfoPermissionIdentifier,
		Description:          "Access to the OpenID Connect user info endpoint",
		ResourceId:           resource.Id,
	}
	permission1, err = database.CreatePermission(nil, permission1)
	if err != nil {
		return err
	}

	permission2 := &entitiesv2.Permission{
		PermissionIdentifier: constants.ManageAccountPermissionIdentifier,
		Description:          "View and update user account data for the current user",
		ResourceId:           resource.Id,
	}
	permission2, err = database.CreatePermission(nil, permission2)
	if err != nil {
		return err
	}

	permission3 := &entitiesv2.Permission{
		PermissionIdentifier: constants.AdminWebsitePermissionIdentifier,
		Description:          "Manage the authorization server settings via the web interface",
		ResourceId:           resource.Id,
	}
	permission3, err = database.CreatePermission(nil, permission3)
	if err != nil {
		return err
	}

	usersPermission, err := database.CreateUsersPermission(nil, &entitiesv2.UsersPermissions{
		UserId:       user.Id,
		PermissionId: permission2.Id,
	})
	if err != nil {
		return err
	}
	fmt.Println(usersPermission)

	usersPermission, err = database.CreateUsersPermission(nil, &entitiesv2.UsersPermissions{
		UserId:       user.Id,
		PermissionId: permission3.Id,
	})
	if err != nil {
		return err
	}

	return nil
}
