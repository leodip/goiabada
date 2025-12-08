package testutil

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MailpitData represents the response from Mailpit's /api/v1/messages endpoint
type MailpitData struct {
	Total         int `json:"total"`
	Count         int `json:"count"`
	MessagesCount int `json:"messages_count"`
	Start         int `json:"start"`
	Messages      []struct {
		ID        string    `json:"ID"`
		MessageID string    `json:"MessageID"`
		Read      bool      `json:"Read"`
		From      Address   `json:"From"`
		To        []Address `json:"To"`
		Cc        []Address `json:"Cc"`
		Bcc       []Address `json:"Bcc"`
		ReplyTo   []Address `json:"ReplyTo"`
		Subject   string    `json:"Subject"`
		Created   time.Time `json:"Created"`
		Tags      []string  `json:"Tags"`
		Size      int       `json:"Size"`
		Snippet   string    `json:"Snippet"`
	} `json:"messages"`
}

// Address represents an email address in Mailpit
type Address struct {
	Name    string `json:"Name"`
	Address string `json:"Address"`
}

// MailpitMessage represents a single message from Mailpit's /api/v1/message/{ID} endpoint
type MailpitMessage struct {
	ID        string    `json:"ID"`
	MessageID string    `json:"MessageID"`
	From      Address   `json:"From"`
	To        []Address `json:"To"`
	Subject   string    `json:"Subject"`
	Created   time.Time `json:"Created"`
	Size      int       `json:"Size"`
	Text      string    `json:"Text"`
	HTML      string    `json:"HTML"`
}

func AssertEmailSent(t *testing.T, to string, containing string) {
	// Mailpit uses /api/v1/messages with query parameter for searching
	// Search syntax: to:email@example.com
	query := url.QueryEscape("to:" + to)
	destUrl := "http://mailpit:8025/api/v1/messages?query=" + query

	resp, err := http.Get(destUrl)
	require.NoError(t, err, "Failed to send GET request")
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Failed to read response body")

	var mailpitData MailpitData
	err = json.Unmarshal(body, &mailpitData)
	require.NoError(t, err, "Failed to unmarshal JSON")

	assert.Equal(t, 1, len(mailpitData.Messages), "expecting to find 1 email")
	if len(mailpitData.Messages) > 0 {
		// Check if the recipient matches
		foundTo := false
		for _, addr := range mailpitData.Messages[0].To {
			if strings.Contains(strings.ToLower(addr.Address), strings.ToLower(to)) {
				foundTo = true
				break
			}
		}
		assert.True(t, foundTo, "Email recipient should contain: %s", to)

		// Get the full message to check the body content
		messageID := mailpitData.Messages[0].ID
		messageUrl := "http://mailpit:8025/api/v1/message/" + messageID
		msgResp, err := http.Get(messageUrl)
		require.NoError(t, err, "Failed to get message details")
		defer func() { _ = msgResp.Body.Close() }()

		msgBody, err := io.ReadAll(msgResp.Body)
		require.NoError(t, err, "Failed to read message body")

		var message MailpitMessage
		err = json.Unmarshal(msgBody, &message)
		require.NoError(t, err, "Failed to unmarshal message JSON")

		// Check if the content is in either HTML or Text body
		bodyContains := strings.Contains(message.HTML, containing) || strings.Contains(message.Text, containing)
		assert.True(t, bodyContains, "Email body should contain: %s", containing)
	} else {
		t.Errorf("No emails found for recipient: %s", to)
	}
}
