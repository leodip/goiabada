package core

import (
	"context"

	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/datav2"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/pkg/errors"
	mail "github.com/xhit/go-simple-mail/v2"
)

type EmailSender struct {
	database datav2.Database
}

func NewEmailSender(database datav2.Database) *EmailSender {
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

	settings := ctx.Value(common.ContextKeySettings).(*entitiesv2.Settings)

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

	smtpEnc, err := enums.SMTPEncryptionFromString(settings.SMTPEncryption)
	if err != nil {
		return errors.Wrap(err, "unable to parse the SMTP encryption")
	}
	switch smtpEnc {
	case enums.SMTPEncryptionSSLTLS:
		server.Encryption = mail.EncryptionSSLTLS
	case enums.SMTPEncryptionSTARTTLS:
		server.Encryption = mail.EncryptionSTARTTLS
	default:
		server.Encryption = mail.EncryptionNone
	}

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
