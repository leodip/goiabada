package core

import (
	"context"
	"time"

	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/pkg/errors"
	mail "github.com/xhit/go-simple-mail/v2"
)

type EmailSender struct {
	database Database
}

func NewEmailSender(database Database) *EmailSender {
	return &EmailSender{
		database: database,
	}
}

type SendEmailInput struct {
	To       string
	Subject  string
	HtmlBody string
}

func (e *EmailSender) SendEmail(ctx context.Context, input *SendEmailInput) error {

	settings := ctx.Value(common.ContextKeySettings).(*entities.Settings)

	server := mail.NewSMTPClient()
	server.Host = settings.SMTPHost
	server.Port = settings.SMTPPort

	if len(settings.SMTPUsername) > 0 {
		server.Username = settings.SMTPUsername
	}

	if len(settings.SMTPPasswordEncrypted) > 0 {
		decryptedPassword, err := lib.DecryptText(settings.SMTPPasswordEncrypted, settings.AESEncryptionKey)
		if err != nil {
			return errors.Wrap(err, "unable to decrypt the SMTP password")
		}

		server.Password = decryptedPassword
	}

	server.Encryption = mail.EncryptionSTARTTLS
	server.ConnectTimeout = 10 * time.Second

	smtpClient, err := server.Connect()
	if err != nil {
		return errors.Wrap(err, "unable to connect to SMTP server")
	}

	email := mail.NewMSG()
	email.SetFrom(settings.SMTPFromName + " <" + settings.SMTPFromEmail + ">").
		AddTo(input.To).
		SetSubject(input.Subject)

	email.SetBody(mail.TextHTML, input.HtmlBody)

	err = email.Send(smtpClient)
	if err != nil {
		return errors.Wrap(err, "unable to send SMTP message")
	}

	return nil
}
