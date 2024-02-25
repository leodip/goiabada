package integrationtests

import "time"

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
