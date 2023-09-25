package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/twilio/twilio-go"
	twilioApi "github.com/twilio/twilio-go/rest/api/v2010"
)

type SMSSender struct {
	database Database
}

func NewSMSSender(database Database) *SMSSender {
	return &SMSSender{
		database: database,
	}
}

type SendSMSInput struct {
	To   string
	Body string
}

func (e *SMSSender) SendSMS(ctx context.Context, input *SendSMSInput) error {

	settings := ctx.Value(common.ContextKeySettings).(*entities.Settings)

	if settings.SMSProvider == "twilio" {

		smsConfigDecrypted, err := lib.DecryptText(settings.SMSConfigEncrypted, settings.AESEncryptionKey)
		if err != nil {
			return customerrors.NewAppError(err, "", "unable to decrypt SMS config", http.StatusInternalServerError)
		}
		var smsTwilioConfig dtos.SMSTwilioConfig
		err = json.Unmarshal([]byte(smsConfigDecrypted), &smsTwilioConfig)
		if err != nil {
			return customerrors.NewAppError(err, "", "unable to unmarshal SMS config", http.StatusInternalServerError)
		}
		client := twilio.NewRestClientWithParams(twilio.ClientParams{
			Username: smsTwilioConfig.AccountSid,
			Password: smsTwilioConfig.AuthToken,
		})

		params := &twilioApi.CreateMessageParams{}
		params.SetTo(input.To)
		params.SetFrom(smsTwilioConfig.From)
		params.SetBody(input.Body)

		_, err = client.Api.CreateMessage(params)
		if err != nil {
			return customerrors.NewAppError(err, "", "unable to send SMS message", http.StatusInternalServerError)
		}
	} else {
		return customerrors.NewAppError(nil, "", fmt.Sprintf("unsupported SMS provider: %v", settings.SMSProvider), http.StatusInternalServerError)
	}

	return nil
}
