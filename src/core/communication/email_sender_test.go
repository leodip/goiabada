package communication

import (
	"context"
	"testing"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/testutil"
	"github.com/leodip/goiabada/core/testutil/fake"
	"github.com/stretchr/testify/assert"
)

func TestSendEmail(t *testing.T) {

	emailSender := NewEmailSender()

	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, &models.Settings{
		SMTPHost:              "mailpit",
		SMTPPort:              1025,
		SMTPUsername:          "",
		SMTPPasswordEncrypted: nil,
		SMTPEncryption:        "none",
		SMTPFromName:          "Test Sender",
		SMTPFromEmail:         "sender@example.com",
	})

	recipient := fake.Email()

	input := &SendEmailInput{
		To:       recipient,
		Subject:  "Test Email",
		HtmlBody: "<p>This is a test email</p>",
	}

	err := emailSender.SendEmail(ctx, input)
	assert.NoError(t, err)

	testutil.AssertEmailSent(t, recipient, "<p>This is a test email</p>")
}
