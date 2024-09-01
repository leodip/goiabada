package testutil

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type MailhogData struct {
	Total int `json:"total"`
	Count int `json:"count"`
	Start int `json:"start"`
	Items []struct {
		ID   string `json:"ID"`
		From struct {
			Relays  any    `json:"Relays"`
			Mailbox string `json:"Mailbox"`
			Domain  string `json:"Domain"`
			Params  string `json:"Params"`
		} `json:"From"`
		To []struct {
			Relays  any    `json:"Relays"`
			Mailbox string `json:"Mailbox"`
			Domain  string `json:"Domain"`
			Params  string `json:"Params"`
		} `json:"To"`
		Content struct {
			Headers struct {
				ContentTransferEncoding []string `json:"Content-Transfer-Encoding"`
				ContentType             []string `json:"Content-Type"`
				Date                    []string `json:"Date"`
				From                    []string `json:"From"`
				MIMEVersion             []string `json:"MIME-Version"`
				MessageID               []string `json:"Message-ID"`
				Received                []string `json:"Received"`
				ReturnPath              []string `json:"Return-Path"`
				Subject                 []string `json:"Subject"`
				To                      []string `json:"To"`
			} `json:"Headers"`
			Body string `json:"Body"`
			Size int    `json:"Size"`
			Mime any    `json:"MIME"`
		} `json:"Content"`
		Created time.Time `json:"Created"`
		Mime    any       `json:"MIME"`
		Raw     struct {
			From string   `json:"From"`
			To   []string `json:"To"`
			Data string   `json:"Data"`
			Helo string   `json:"Helo"`
		} `json:"Raw"`
	} `json:"items"`
}

func AssertEmailSent(t *testing.T, to string, containing string) {
	destUrl := "http://mailhog:8025/api/v2/search?kind=to&query=" + to

	resp, err := http.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var mailhogData MailhogData

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	err = json.Unmarshal(body, &mailhogData)
	if err != nil {
		log.Fatal(err)
	}

	assert.Equal(t, 1, len(mailhogData.Items), "expecting to find 1 email")
	assert.True(t, strings.Contains(mailhogData.Items[0].Content.Headers.To[0], to))
	assert.True(t, strings.Contains(mailhogData.Items[0].Content.Body, containing))
}
