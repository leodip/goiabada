package integrationtests

import (
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/datav2"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
	"gorm.io/gorm"
)

func seedTestDatav2(d datav2.Database) error {

	res, _ := d.GetResourceByResourceIdentifier(nil, "backend-svcA")
	if res != nil {
		// already seeded
		slog.Info("no need to seed test data")
		return nil
	}

	slog.Info("seeding test data")

	resource := &entitiesv2.Resource{
		ResourceIdentifier: "backend-svcA",
		Description:        "Backend service A (integration tests)",
	}
	err := d.CreateResource(nil, resource)
	if err != nil {
		return err
	}

	permission1 := &entitiesv2.Permission{
		PermissionIdentifier: "create-product",
		Description:          "Create new products",
		ResourceId:           resource.Id,
	}
	err = d.CreatePermission(nil, permission1)
	if err != nil {
		return err
	}

	permission2 := &entitiesv2.Permission{
		PermissionIdentifier: "read-product",
		Description:          "Read products",
		ResourceId:           resource.Id,
	}
	if err != nil {
		return err
	}
	err = d.CreatePermission(nil, permission2)
	if err != nil {
		return err
	}

	resource = &entitiesv2.Resource{
		ResourceIdentifier: "backend-svcB",
		Description:        "Backend service B (integration tests)",
	}
	err = d.CreateResource(nil, resource)
	if err != nil {
		return err
	}

	permission3 := &entitiesv2.Permission{
		PermissionIdentifier: "read-info",
		Description:          "Read info",
		ResourceId:           resource.Id,
	}
	err = d.CreatePermission(nil, permission3)
	if err != nil {
		return err
	}

	permission4 := &entitiesv2.Permission{
		PermissionIdentifier: "write-info",
		Description:          "Write info",
		ResourceId:           resource.Id,
	}
	err = d.CreatePermission(nil, permission4)
	if err != nil {
		return err
	}

	group1 := &entitiesv2.Group{
		GroupIdentifier:      "site-admins",
		Description:          "Site admins test group",
		IncludeInIdToken:     false,
		IncludeInAccessToken: true,
	}
	err = d.CreateGroup(nil, group1)
	if err != nil {
		return err
	}

	group2 := &entitiesv2.Group{
		GroupIdentifier:      "product-admins",
		Description:          "Product admins test group",
		IncludeInIdToken:     false,
		IncludeInAccessToken: true,
	}
	err = d.CreateGroup(nil, group2)
	if err != nil {
		return err
	}

	passwordHash, err := lib.HashPassword("abc123")
	if err != nil {
		panic(err)
	}

	dob := time.Date(1976, 11, 18, 0, 0, 0, 0, time.Local)
	user := &entitiesv2.User{
		Enabled:             true,
		Subject:             uuid.New(),
		Username:            "mauro1",
		PasswordHash:        passwordHash,
		GivenName:           "Mauro",
		MiddleName:          "Dantes",
		FamilyName:          "Golias",
		Email:               "mauro@outlook.com",
		EmailVerified:       true,
		ZoneInfoCountryName: "Brazil",
		ZoneInfo:            "America/Sao_Paulo",
		Locale:              "pt-BR",
		BirthDate:           &dob,
		PhoneNumber:         "+351 912156387",
		PhoneNumberVerified: true,
		Nickname:            "maurogo",
		Website:             "https://www.maurogo.com",
		Gender:              enums.GenderMale.String(),
		AddressLine1:        "Rua de São Romão 138",
		AddressLine2:        "Apto 5A",
		AddressLocality:     "Vila Nova de Gaia",
		AddressRegion:       "Porto",
		AddressPostalCode:   "4400-089",
		AddressCountry:      "PRT",
		OTPSecret:           "ILMGDC577J4A4HTR5POU4BU5H5W7VYM2",
		OTPEnabled:          true,
	}

	err = d.CreateUser(nil, user)
	if err != nil {
		return err
	}

	accountPerm, err := d.GetPermissionByPermissionIdentifier(nil, constants.ManageAccountPermissionIdentifier)
	if err != nil {
		return err
	}

	err = d.CreateUserPermission(nil, &entitiesv2.UserPermission{
		UserId:       user.Id,
		PermissionId: accountPerm.Id,
	})
	if err != nil {
		return err
	}
	err = d.CreateUserPermission(nil, &entitiesv2.UserPermission{
		UserId:       user.Id,
		PermissionId: permission2.Id,
	})
	if err != nil {
		return err
	}
	err = d.CreateUserPermission(nil, &entitiesv2.UserPermission{
		UserId:       user.Id,
		PermissionId: permission4.Id,
	})
	if err != nil {
		return err
	}

	passwordHash, err = lib.HashPassword("asd123")
	if err != nil {
		panic(err)
	}

	dob = time.Date(1975, 6, 15, 0, 0, 0, 0, time.Local)
	user = &entitiesv2.User{
		Enabled:             true,
		Subject:             uuid.New(),
		Username:            "vivi1",
		PasswordHash:        passwordHash,
		GivenName:           "Viviane",
		MiddleName:          "Moura",
		FamilyName:          "Albuquerque",
		Email:               "viviane@gmail.com",
		EmailVerified:       true,
		ZoneInfoCountryName: "Italy",
		ZoneInfo:            "Europe/Rome",
		Locale:              "it-IT",
		BirthDate:           &dob,
		PhoneNumber:         "+351 912547896",
		PhoneNumberVerified: true,
		Nickname:            "vivialbu",
		Website:             "https://www.vivialbu.com",
		Gender:              enums.GenderFemale.String(),
		AddressLine1:        "Rua Lauro Muller 125",
		AddressLine2:        "Bairro Velha",
		AddressLocality:     "Blumenau",
		AddressRegion:       "SC",
		AddressPostalCode:   "88131-601",
		AddressCountry:      "BRA",
	}

	err = d.CreateUser(nil, user)
	if err != nil {
		return err
	}

	err = d.CreateUserPermission(nil, &entitiesv2.UserPermission{
		UserId:       user.Id,
		PermissionId: accountPerm.Id,
	})
	if err != nil {
		return err
	}
	err = d.CreateUserPermission(nil, &entitiesv2.UserPermission{
		UserId:       user.Id,
		PermissionId: permission1.Id,
	})
	if err != nil {
		return err
	}
	err = d.CreateUserPermission(nil, &entitiesv2.UserPermission{
		UserId:       user.Id,
		PermissionId: permission2.Id,
	})
	if err != nil {
		return err
	}

	user.Attributes = []entitiesv2.UserAttribute{
		{
			Key:                  "my-key",
			Value:                "10",
			UserId:               user.Id,
			IncludeInIdToken:     true,
			IncludeInAccessToken: true,
		},
		{
			Key:                  "another-key",
			Value:                "20",
			UserId:               user.Id,
			IncludeInIdToken:     false,
			IncludeInAccessToken: false,
		},
		{
			Key:                  "foo-key",
			Value:                "30",
			UserId:               user.Id,
			IncludeInIdToken:     true,
			IncludeInAccessToken: false,
		},
		{
			Key:                  "bar-key",
			Value:                "40",
			UserId:               user.Id,
			IncludeInIdToken:     false,
			IncludeInAccessToken: true,
		},
	}
	err = d.CreateUserAttribute(nil, &user.Attributes[0])
	if err != nil {
		return err
	}
	err = d.CreateUserAttribute(nil, &user.Attributes[1])
	if err != nil {
		return err
	}
	err = d.CreateUserAttribute(nil, &user.Attributes[2])
	if err != nil {
		return err
	}
	err = d.CreateUserAttribute(nil, &user.Attributes[3])
	if err != nil {
		return err
	}

	settings, err := d.GetSettingsById(nil, 1)
	if err != nil {
		return err
	}

	clientSecret := lib.GenerateSecureRandomString(60)
	encClientSecret, _ := lib.EncryptText(clientSecret, settings.AESEncryptionKey)
	client := &entitiesv2.Client{
		ClientIdentifier:                        "test-client-1",
		Description:                             "Test client 1 (integration tests)",
		Enabled:                                 true,
		ConsentRequired:                         true,
		IsPublic:                                false,
		ClientSecretEncrypted:                   encClientSecret,
		RedirectURIs:                            []entitiesv2.RedirectURI{{URI: "https://goiabada-test-client:8090/callback.html"}, {URI: "https://oauthdebugger.com/debug"}},
		Permissions:                             []entitiesv2.Permission{*permission1, *permission3},
		DefaultAcrLevel:                         enums.AcrLevel2,
		IncludeOpenIDConnectClaimsInAccessToken: enums.ThreeStateSettingDefault.String(),
		AuthorizationCodeEnabled:                true,
		ClientCredentialsEnabled:                true,
	}
	err = d.CreateClient(nil, client)
	if err != nil {
		return err
	}

	for _, uri := range client.RedirectURIs {
		err = d.CreateRedirectURI(nil, &uri)
		if err != nil {
			return err
		}
	}

	// for _, perm := range clientP.Permissions {
	// 	_, err = d.CreateClientPermission(nil, entitiesv2.ClientPermission{
	// 		ClientId:     clientP.Id,
	// 		PermissionId: perm.Id,
	// 	})
	// 	if err != nil {
	// 		return err
	// 	}
	// }

	// client = entities.Client{
	// 	ClientIdentifier:                        "test-client-2",
	// 	Description:                             "Test client 2 (integration tests)",
	// 	Enabled:                                 true,
	// 	ConsentRequired:                         false,
	// 	IsPublic:                                true,
	// 	RedirectURIs:                            []entities.RedirectURI{{URI: "https://goiabada-test-client:8090/callback.html"}, {URI: "https://oauthdebugger.com/debug"}},
	// 	DefaultAcrLevel:                         enums.AcrLevel2,
	// 	IncludeOpenIDConnectClaimsInAccessToken: enums.ThreeStateSettingDefault.String(),
	// 	AuthorizationCodeEnabled:                true,
	// 	ClientCredentialsEnabled:                false,
	// }
	// d.DB.Create(&client)

	// client = entities.Client{
	// 	ClientIdentifier:                        "test-client-3",
	// 	Description:                             "Test client 3 (integration tests)",
	// 	Enabled:                                 false,
	// 	ConsentRequired:                         false,
	// 	IsPublic:                                true,
	// 	RedirectURIs:                            []entities.RedirectURI{{URI: "https://goiabada-test-client:8090/callback.html"}, {URI: "https://oauthdebugger.com/debug"}},
	// 	DefaultAcrLevel:                         enums.AcrLevel2,
	// 	IncludeOpenIDConnectClaimsInAccessToken: enums.ThreeStateSettingDefault.String(),
	// 	AuthorizationCodeEnabled:                true,
	// 	ClientCredentialsEnabled:                false,
	// }
	// d.DB.Create(&client)

	// settings.SMTPHost = "mailhog"
	// settings.SMTPPort = 1025
	// settings.SMTPFromName = "Goiabada"
	// settings.SMTPFromEmail = "noreply@goiabada.dev"
	// settings.SMTPUsername = ""
	// settings.SMTPPasswordEncrypted = nil
	// settings.SMTPEncryption = enums.SMTPEncryptionNone.String()
	// settings.SMTPEnabled = true

	// settings.SMSProvider = "test"
	// settings.SMSConfigEncrypted = nil

	// d.DB.Save(settings)

	// generateUsers(d.DB)

	// slog.Info("finished seeding test data")

	return nil
}

func generateUsersv2(db *gorm.DB) {

	// tz := lib.GetTimeZones()
	// locales := lib.GetLocales()
	// countries := countries.AllInfo()
	// phoneCountries := lib.GetPhoneCountries()

	// var accountPermission *entities.Permission
	// db.Where("permission_identifier = ?", constants.ManageAccountPermissionIdentifier).First(&accountPermission)

	// const number = 100
	// for i := 0; i < number; i++ {
	// 	dob := gofakeit.Date()

	// 	email := gofakeit.Email()
	// 	otpEnabled := false
	// 	otpSecret := ""
	// 	if gofakeit.Bool() {
	// 		otpEnabled = true
	// 	}
	// 	if otpEnabled {
	// 		key, err := totp.Generate(totp.GenerateOpts{
	// 			Issuer:      "Integration test",
	// 			AccountName: email,
	// 		})
	// 		if err != nil {
	// 			panic(err)
	// 		}
	// 		otpSecret = key.Secret()
	// 	}

	// 	password := "abc123"
	// 	passwordHash, err := lib.HashPassword(password)
	// 	if err != nil {
	// 		panic(err)
	// 	}

	// 	idx := gofakeit.Number(0, len(tz)-1)
	// 	timezone := tz[idx]

	// 	idx = gofakeit.Number(0, len(locales)-1)
	// 	locale := locales[idx]

	// 	idx = gofakeit.Number(0, len(countries)-1)
	// 	country := countries[idx]

	// 	idx = gofakeit.Number(0, len(phoneCountries)-1)
	// 	phoneCountry := phoneCountries[idx]

	// 	user := &entities.User{
	// 		Subject:             uuid.New(),
	// 		Username:            gofakeit.Username(),
	// 		Enabled:             gofakeit.Bool(),
	// 		GivenName:           gofakeit.FirstName(),
	// 		MiddleName:          gofakeit.MiddleName(),
	// 		FamilyName:          gofakeit.LastName(),
	// 		Email:               email,
	// 		EmailVerified:       gofakeit.Bool(),
	// 		ZoneInfoCountryName: timezone.CountryName,
	// 		ZoneInfo:            timezone.Zone,
	// 		Locale:              locale.Id,
	// 		PhoneNumber:         phoneCountry.Code + " " + gofakeit.Phone(),
	// 		PhoneNumberVerified: gofakeit.Bool(),
	// 		Nickname:            gofakeit.Username(),
	// 		Website:             gofakeit.URL(),
	// 		Gender:              gofakeit.RandomString([]string{"female", "male", "other"}),
	// 		BirthDate:           &dob,
	// 		AddressLine1:        gofakeit.StreetName(),
	// 		AddressLine2:        gofakeit.StreetNumber(),
	// 		AddressLocality:     gofakeit.City(),
	// 		AddressRegion:       gofakeit.State(),
	// 		AddressPostalCode:   gofakeit.Zip(),
	// 		AddressCountry:      country.Alpha3,
	// 		OTPEnabled:          otpEnabled,
	// 		OTPSecret:           otpSecret,
	// 		PasswordHash:        passwordHash,
	// 		Permissions:         []entities.Permission{*accountPermission},
	// 	}
	// 	result := db.Save(user)
	// 	if result.Error != nil {
	// 		panic(result.Error)
	// 	}
	// }
}
