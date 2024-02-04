package datav2

import (
	"fmt"

	"github.com/gorilla/securecookie"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
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
		RedirectURIs: []entitiesv2.RedirectURI{
			{URI: lib.GetBaseUrl() + "/auth/callback"},
		},
	}
	client1, err := database.CreateClientWithAssociations(nil, client1, []enums.ClientAssociations{enums.ClientAssociationsRedirectURIs})
	if err != nil {
		return err
	}
	fmt.Println(client1)

	return nil
}
