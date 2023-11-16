package integrationtests

import (
	"time"

	"log/slog"

	"github.com/biter777/countries"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
)

func seedTestData(d *data.Database) {

	res, _ := d.GetResourceByResourceIdentifier("backend-svcA")
	if res != nil {
		// already seeded
		slog.Info("no need to seed test data")
		return
	}

	slog.Info("seeding test data")

	resource := entities.Resource{
		ResourceIdentifier: "backend-svcA",
		Description:        "Backend service A (integration tests)",
	}
	d.DB.Create(&resource)

	permission1 := entities.Permission{
		PermissionIdentifier: "create-product",
		Description:          "Create new products",
		ResourceId:           resource.Id,
	}
	d.DB.Create(&permission1)

	permission2 := entities.Permission{
		PermissionIdentifier: "read-product",
		Description:          "Read products",
		ResourceId:           resource.Id,
	}
	d.DB.Create(&permission2)

	resource = entities.Resource{
		ResourceIdentifier: "backend-svcB",
		Description:        "Backend service B (integration tests)",
	}
	d.DB.Create(&resource)

	permission3 := entities.Permission{
		PermissionIdentifier: "read-info",
		Description:          "Read info",
		ResourceId:           resource.Id,
	}
	d.DB.Create(&permission3)

	permission4 := entities.Permission{
		PermissionIdentifier: "write-info",
		Description:          "Write info",
		ResourceId:           resource.Id,
	}
	d.DB.Create(&permission4)

	group1 := entities.Group{
		GroupIdentifier:      "site-admins",
		Description:          "Site admins test group",
		IncludeInIdToken:     false,
		IncludeInAccessToken: true,
	}
	d.DB.Create(&group1)

	group2 := entities.Group{
		GroupIdentifier:      "product-admins",
		Description:          "Product admins test group",
		IncludeInIdToken:     false,
		IncludeInAccessToken: true,
	}
	d.DB.Create(&group2)

	passwordHash, err := lib.HashPassword("abc123")
	if err != nil {
		panic(err)
	}

	dob := time.Date(1976, 11, 18, 0, 0, 0, 0, time.Local)
	user := entities.User{
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

	accountPerm, _ := d.GetPermissionByPermissionIdentifier(constants.ManageAccountPermissionIdentifier)

	user.Permissions = []entities.Permission{*accountPerm, permission2, permission4}
	user.Groups = []entities.Group{group1, group2}
	d.DB.Create(&user)

	passwordHash, err = lib.HashPassword("asd123")
	if err != nil {
		panic(err)
	}

	dob = time.Date(1975, 6, 15, 0, 0, 0, 0, time.Local)
	user = entities.User{
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
	user.Permissions = []entities.Permission{*accountPerm, permission1, permission2}
	d.DB.Create(&user)
	user.Attributes = []entities.UserAttribute{
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
	d.DB.Save(&user)

	settings, _ := d.GetSettings()

	clientSecret := lib.GenerateSecureRandomString(60)
	encClientSecret, _ := lib.EncryptText(clientSecret, settings.AESEncryptionKey)
	client := entities.Client{
		ClientIdentifier:                        "test-client-1",
		Description:                             "Test client 1 (integration tests)",
		Enabled:                                 true,
		ConsentRequired:                         true,
		IsPublic:                                false,
		ClientSecretEncrypted:                   encClientSecret,
		RedirectURIs:                            []entities.RedirectURI{{URI: "https://goiabada.local:8090/callback.html"}, {URI: "https://oauthdebugger.com/debug"}},
		Permissions:                             []entities.Permission{permission1, permission3},
		DefaultAcrLevel:                         enums.AcrLevel2,
		IncludeOpenIDConnectClaimsInAccessToken: enums.ThreeStateSettingDefault.String(),
		AuthorizationCodeEnabled:                true,
		ClientCredentialsEnabled:                true,
	}
	d.DB.Create(&client)

	client = entities.Client{
		ClientIdentifier:                        "test-client-2",
		Description:                             "Test client 2 (integration tests)",
		Enabled:                                 true,
		ConsentRequired:                         false,
		IsPublic:                                true,
		RedirectURIs:                            []entities.RedirectURI{{URI: "https://goiabada.local:8090/callback.html"}, {URI: "https://oauthdebugger.com/debug"}},
		DefaultAcrLevel:                         enums.AcrLevel2,
		IncludeOpenIDConnectClaimsInAccessToken: enums.ThreeStateSettingDefault.String(),
		AuthorizationCodeEnabled:                true,
		ClientCredentialsEnabled:                false,
	}
	d.DB.Create(&client)

	client = entities.Client{
		ClientIdentifier:                        "test-client-3",
		Description:                             "Test client 3 (integration tests)",
		Enabled:                                 false,
		ConsentRequired:                         false,
		IsPublic:                                true,
		RedirectURIs:                            []entities.RedirectURI{{URI: "https://goiabada.local:8090/callback.html"}, {URI: "https://oauthdebugger.com/debug"}},
		DefaultAcrLevel:                         enums.AcrLevel2,
		IncludeOpenIDConnectClaimsInAccessToken: enums.ThreeStateSettingDefault.String(),
		AuthorizationCodeEnabled:                true,
		ClientCredentialsEnabled:                false,
	}
	d.DB.Create(&client)

	settings.SMTPHost = "mailhog"
	settings.SMTPPort = 1025
	settings.SMTPFromName = "Goiabada"
	settings.SMTPFromEmail = "noreply@goiabada.dev"
	settings.SMTPUsername = ""
	settings.SMTPPasswordEncrypted = nil
	settings.SMTPEncryption = enums.SMTPEncryptionNone.String()
	settings.SMTPEnabled = true

	settings.SMSProvider = ""
	settings.SMSConfigEncrypted = nil

	d.DB.Save(settings)

	generateUsers(d.DB)

	slog.Info("finished seeding test data")
}

func generateUsers(db *gorm.DB) {

	tz := lib.GetTimeZones()
	locales := lib.GetLocales()
	countries := countries.AllInfo()
	phoneCountries := lib.GetPhoneCountries()

	var accountPermission *entities.Permission
	db.Where("permission_identifier = ?", constants.ManageAccountPermissionIdentifier).First(&accountPermission)

	const number = 100
	for i := 0; i < number; i++ {
		dob := gofakeit.Date()

		email := gofakeit.Email()
		otpEnabled := false
		otpSecret := ""
		if gofakeit.Bool() {
			otpEnabled = true
		}
		if otpEnabled {
			key, err := totp.Generate(totp.GenerateOpts{
				Issuer:      "Integration test",
				AccountName: email,
			})
			if err != nil {
				panic(err)
			}
			otpSecret = key.Secret()
		}

		password := "abc123"
		passwordHash, err := lib.HashPassword(password)
		if err != nil {
			panic(err)
		}

		idx := gofakeit.Number(0, len(tz)-1)
		timezone := tz[idx]

		idx = gofakeit.Number(0, len(locales)-1)
		locale := locales[idx]

		idx = gofakeit.Number(0, len(countries)-1)
		country := countries[idx]

		idx = gofakeit.Number(0, len(phoneCountries)-1)
		phoneCountry := phoneCountries[idx]

		user := &entities.User{
			Subject:             uuid.New(),
			Username:            gofakeit.Username(),
			Enabled:             gofakeit.Bool(),
			GivenName:           gofakeit.FirstName(),
			MiddleName:          gofakeit.MiddleName(),
			FamilyName:          gofakeit.LastName(),
			Email:               email,
			EmailVerified:       gofakeit.Bool(),
			ZoneInfoCountryName: timezone.CountryName,
			ZoneInfo:            timezone.Zone,
			Locale:              locale.Id,
			PhoneNumber:         phoneCountry.Code + " " + gofakeit.Phone(),
			PhoneNumberVerified: gofakeit.Bool(),
			Nickname:            gofakeit.Username(),
			Website:             gofakeit.URL(),
			Gender:              gofakeit.RandomString([]string{"female", "male", "other"}),
			BirthDate:           &dob,
			AddressLine1:        gofakeit.StreetName(),
			AddressLine2:        gofakeit.StreetNumber(),
			AddressLocality:     gofakeit.City(),
			AddressRegion:       gofakeit.State(),
			AddressPostalCode:   gofakeit.Zip(),
			AddressCountry:      country.Alpha3,
			OTPEnabled:          otpEnabled,
			OTPSecret:           otpSecret,
			PasswordHash:        passwordHash,
			Permissions:         []entities.Permission{*accountPermission},
		}
		result := db.Save(user)
		if result.Error != nil {
			panic(result.Error)
		}
	}
}
