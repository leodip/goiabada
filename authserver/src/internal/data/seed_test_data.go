package data

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/spf13/viper"
)

func (d *Database) seedTestData() error {

	resource := entities.Resource{
		ResourceIdentifier: "backend-svcA",
		Description:        "Backend service A",
	}
	d.DB.Create(&resource)

	permission1 := entities.Permission{
		PermissionIdentifier: "create-product",
		Description:          "Create new products",
		ResourceID:           resource.ID,
	}
	d.DB.Create(&permission1)

	permission2 := entities.Permission{
		PermissionIdentifier: "read-product",
		Description:          "Read products",
		ResourceID:           resource.ID,
	}
	d.DB.Create(&permission2)

	resource = entities.Resource{
		ResourceIdentifier: "backend-svcB",
		Description:        "Backend service B",
	}
	d.DB.Create(&resource)

	permission3 := entities.Permission{
		PermissionIdentifier: "read-info",
		Description:          "Read info",
		ResourceID:           resource.ID,
	}
	d.DB.Create(&permission3)

	role1 := entities.Role{
		RoleIdentifier: "site-admin",
		Description:    "Site admin test role",
	}
	d.DB.Create(&role1)

	role2 := entities.Role{
		RoleIdentifier: "product-admin",
		Description:    "Product admin test role",
	}
	d.DB.Create(&role2)

	passwordHash, _ := lib.HashPassword("abc123")
	dob := time.Date(1979, 12, 22, 0, 0, 0, 0, time.Local)
	user := entities.User{
		Subject:             uuid.New(),
		Username:            "mauro1",
		PasswordHash:        passwordHash,
		GivenName:           "Mauro",
		MiddleName:          "Dantes",
		FamilyName:          "Golias",
		Email:               "mauro@outlook.com",
		EmailVerified:       true,
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
	}
	user.Permissions = []entities.Permission{permission2}
	user.Roles = []entities.Role{role1, role2}
	d.DB.Create(&user)

	passwordHash, _ = lib.HashPassword("asd123")

	dob = time.Date(1981, 1, 22, 0, 0, 0, 0, time.Local)
	user = entities.User{
		Subject:             uuid.New(),
		Username:            "vivi1",
		PasswordHash:        passwordHash,
		GivenName:           "Viviane",
		MiddleName:          "Moura",
		FamilyName:          "Albuquerque",
		Email:               "viviane@gmail.com",
		EmailVerified:       true,
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
	user.Permissions = []entities.Permission{permission1, permission2}
	d.DB.Create(&user)

	settings, _ := d.GetSettings()

	clientSecret := lib.GenerateSecureRandomString(60)
	encClientSecret, _ := lib.EncryptText(clientSecret, settings.AESEncryptionKey)
	client := entities.Client{
		ClientIdentifier:      "test-client-1",
		Enabled:               true,
		ConsentRequired:       true,
		IsPublic:              false,
		ClientSecretEncrypted: encClientSecret,
		RedirectUris:          []entities.RedirectUri{{Uri: "https://goiabada.local:8090/callback.html"}, {Uri: "https://oauthdebugger.com/debug"}},
		Permissions:           []entities.Permission{permission1, permission3},
	}
	d.DB.Create(&client)

	client = entities.Client{
		ClientIdentifier: "test-client-2",
		Enabled:          true,
		ConsentRequired:  false,
		IsPublic:         true,
		RedirectUris:     []entities.RedirectUri{{Uri: "https://goiabada.local:8090/callback.html"}, {Uri: "https://oauthdebugger.com/debug"}},
	}
	d.DB.Create(&client)

	settings.SMTPHost = viper.GetString("SMTP.Host")
	settings.SMTPPort = viper.GetInt("SMTP.Port")
	settings.SMTPFromName = viper.GetString("SMTP.FromName")
	settings.SMTPFromEmail = viper.GetString("SMTP.FromEmail")
	settings.SMTPUsername = viper.GetString("SMTP.Username")

	smtpPasswordEnc, _ := lib.EncryptText(viper.GetString("SMTP.Password"), settings.AESEncryptionKey)
	settings.SMTPPasswordEncrypted = smtpPasswordEnc

	twilioConfig := dtos.SMSTwilioConfig{
		AccountSid: viper.GetString("Twilio.AccountSid"),
		AuthToken:  viper.GetString("Twilio.AuthToken"),
		From:       viper.GetString("Twilio.From"),
	}
	jsonData, _ := json.Marshal(twilioConfig)
	settings.SMSProvider = "twilio"
	smsConfigEncrypted, _ := lib.EncryptText(string(jsonData), settings.AESEncryptionKey)
	settings.SMSConfigEncrypted = smsConfigEncrypted

	d.DB.Save(settings)

	return nil
}
