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

// ClearMailpit deletes all messages from Mailpit
func ClearMailpit(t *testing.T) {
	req, err := http.NewRequest(http.MethodDelete, "http://mailpit:8025/api/v1/messages", nil)
	require.NoError(t, err, "Failed to create DELETE request")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err, "Failed to clear Mailpit messages")
	defer func() { _ = resp.Body.Close() }()
}

// deleteMailpitMessage deletes a specific message from Mailpit
func deleteMailpitMessage(t *testing.T, messageID string) {
	req, err := http.NewRequest(http.MethodDelete, "http://mailpit:8025/api/v1/messages",
		strings.NewReader(`{"ids":["`+messageID+`"]}`))
	if err != nil {
		t.Logf("Warning: Failed to create delete request for message %s: %v", messageID, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Logf("Warning: Failed to delete message %s: %v", messageID, err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
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

	require.GreaterOrEqual(t, len(mailpitData.Messages), 1, "expecting to find at least 1 email for recipient: %s", to)

	// Find the most recent message (first in the list) that matches our criteria
	var matchedMessageID string
	var matchFound bool

	for _, msg := range mailpitData.Messages {
		// Check if the recipient matches
		foundTo := false
		for _, addr := range msg.To {
			if strings.EqualFold(addr.Address, to) {
				foundTo = true
				break
			}
		}
		if !foundTo {
			continue
		}

		// Get the full message to check the body content
		messageID := msg.ID
		messageUrl := "http://mailpit:8025/api/v1/message/" + messageID
		msgResp, err := http.Get(messageUrl)
		require.NoError(t, err, "Failed to get message details")

		msgBody, err := io.ReadAll(msgResp.Body)
		_ = msgResp.Body.Close()
		require.NoError(t, err, "Failed to read message body")

		var message MailpitMessage
		err = json.Unmarshal(msgBody, &message)
		require.NoError(t, err, "Failed to unmarshal message JSON")

		// Check if the content is in either HTML or Text body
		if strings.Contains(message.HTML, containing) || strings.Contains(message.Text, containing) {
			matchFound = true
			matchedMessageID = messageID
			break
		}
	}

	assert.True(t, matchFound, "Email body should contain: %s", containing)

	// Clean up: delete the matched message to avoid accumulation
	if matchedMessageID != "" {
		deleteMailpitMessage(t, matchedMessageID)
	}
}
