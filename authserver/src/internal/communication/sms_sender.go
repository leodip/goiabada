package communication

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/models"
	"github.com/pkg/errors"
	"github.com/twilio/twilio-go"
	twilioApi "github.com/twilio/twilio-go/rest/api/v2010"
)

type SMSSender struct {
	database data.Database
}

func NewSMSSender(database data.Database) *SMSSender {
	return &SMSSender{
		database: database,
	}
}

type SendSMSInput struct {
	To   string
	Body string
}

func (e *SMSSender) SendSMS(ctx context.Context, input *SendSMSInput) error {
	settings := ctx.Value(constants.ContextKeySettings).(*models.Settings)

	switch settings.SMSProvider {
	case "twilio":
		smsConfigDecrypted, err := lib.DecryptText(settings.SMSConfigEncrypted, settings.AESEncryptionKey)
		if err != nil {
			return errors.Wrap(err, "unable to decrypt SMS config")
		}

		var smsTwilioConfig SMSTwilioConfig
		err = json.Unmarshal([]byte(smsConfigDecrypted), &smsTwilioConfig)
		if err != nil {
			return errors.Wrap(err, "unable to unmarshal SMS config")
		}

		client := twilio.NewRestClientWithParams(twilio.ClientParams{
			Username: smsTwilioConfig.AccountSID,
			Password: smsTwilioConfig.AuthToken,
		})

		params := &twilioApi.CreateMessageParams{}
		params.SetTo(input.To)
		params.SetFrom(smsTwilioConfig.From)
		params.SetBody(input.Body)

		_, err = client.Api.CreateMessage(params)
		if err != nil {
			return errors.Wrap(err, "unable to send SMS message")
		}

	case "test":
		// Write the message to a text file so we can assert on them later
		filePath := filepath.Join(os.TempDir(), "sms_messages.txt")
		file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return errors.Wrap(err, "unable to open messages.txt")
		}
		defer file.Close()

		_, err = file.WriteString(fmt.Sprintf("%s|%s\n", input.To, input.Body))
		if err != nil {
			return errors.Wrap(err, "unable to write to messages.txt")
		}

	default:
		return errors.WithStack(fmt.Errorf("unsupported SMS provider: %v", settings.SMSProvider))
	}

	return nil
}
