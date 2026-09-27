// Package mailpit is the one client this tree has for Mailpit's HTTP API, which the unit tier's
// real-SMTP test and the integration tier's emailed-link flows read sent mail back through.
//
// It takes its base URL from the caller rather than hard-coding the dev container's, and every
// request is bounded by the client's timeout, so a Mailpit that stops answering fails the test that
// asked instead of hanging the tier. The query methods return errors; AssertEmailSent fails through
// testutil.Reporter rather than testify, so its failure paths are driven under testutil.RunGuard
// the way the guards' are (#431). No binary imports it.
package mailpit

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/testutil"
)

// defaultTimeout bounds each request New's client makes, connect through the last body byte.
const defaultTimeout = 10 * time.Second

// listLimit is how many of the newest messages List asks for. Mailpit's own default is 50, and
// the integration tier sends more than that in one run.
const listLimit = 200

// Client talks to one Mailpit instance.
type Client struct {
	baseURL string
	http    *http.Client
}

// New returns a client for the Mailpit whose API is served at baseURL, for example
// "http://mailpit:8025".
func New(baseURL string) *Client {
	return newClient(baseURL, defaultTimeout)
}

func newClient(baseURL string, timeout time.Duration) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: timeout},
	}
}

// Address is a mailbox as Mailpit reports it.
type Address struct {
	Name    string `json:"Name"`
	Address string `json:"Address"`
}

// Summary is one entry of Mailpit's message list, which carries no body.
type Summary struct {
	ID        string    `json:"ID"`
	MessageID string    `json:"MessageID"`
	From      Address   `json:"From"`
	To        []Address `json:"To"`
	Subject   string    `json:"Subject"`
	Created   time.Time `json:"Created"`
}

// Message is one message as Mailpit parsed it, bodies included.
type Message struct {
	ID        string    `json:"ID"`
	MessageID string    `json:"MessageID"`
	From      Address   `json:"From"`
	To        []Address `json:"To"`
	Subject   string    `json:"Subject"`
	Created   time.Time `json:"Created"`
	Text      string    `json:"Text"`
	HTML      string    `json:"HTML"`
}

// List returns the newest messages Mailpit holds, at most listLimit of them, newest first.
//
// It takes no search: /api/v1/messages ignores a query parameter, which is what the client this
// replaced sent and why it had filtered by recipient itself all along (#431).
func (c *Client) List() ([]Summary, error) {
	var listing struct {
		Messages []Summary `json:"messages"`
	}
	target := c.baseURL + "/api/v1/messages?limit=" + strconv.Itoa(listLimit)
	if err := c.getJSON(target, &listing); err != nil {
		return nil, errs.Wrap(err, "unable to list the messages Mailpit holds")
	}
	return listing.Messages, nil
}

// Message returns one message, bodies included.
func (c *Client) Message(id string) (Message, error) {
	var message Message
	if err := c.getJSON(c.baseURL+"/api/v1/message/"+url.PathEscape(id), &message); err != nil {
		return Message{}, errs.Wrapf(err, "unable to read message %s from Mailpit", id)
	}
	return message, nil
}

// Delete removes one message, so a suite that sends many does not read its own history back.
func (c *Client) Delete(id string) error {
	payload, err := json.Marshal(map[string][]string{"IDs": {id}})
	if err != nil {
		return errs.Wrap(err, "unable to encode the delete request")
	}
	resp, err := c.do(http.MethodDelete, c.baseURL+"/api/v1/messages", bytes.NewReader(payload))
	if err != nil {
		return errs.Wrapf(err, "unable to delete message %s from Mailpit", id)
	}
	_ = resp.Body.Close()
	return nil
}

// AssertEmailSent finds the newest message Mailpit received for to whose HTML or text body
// contains containing, deletes it, and returns it as Mailpit parsed it, so a caller can go on to
// assert on headers a real MIME parser read back rather than on the bytes the sender wrote (#274).
//
// A miss is fatal rather than an error: the message is returned, and a caller continuing past a
// miss would assert on a zero value and report a second, misleading failure about its headers. A
// delete that fails is an error, since the message was found but the next test would read it too.
func (c *Client) AssertEmailSent(r testutil.Reporter, to string, containing string) Message {
	r.Helper()

	summaries, err := c.List()
	if err != nil {
		r.Fatalf("%v", err)
	}

	addressed := 0
	for _, summary := range summaries {
		if !addressedTo(summary, to) {
			continue
		}
		addressed++

		message, err := c.Message(summary.ID)
		if err != nil {
			r.Fatalf("%v", err)
		}
		if !strings.Contains(message.HTML, containing) && !strings.Contains(message.Text, containing) {
			continue
		}

		if err := c.Delete(summary.ID); err != nil {
			r.Errorf("%v", err)
		}
		return message
	}

	if addressed == 0 {
		r.Fatalf("no message to %s among the %d newest Mailpit holds", to, len(summaries))
	}
	r.Fatalf("none of the %d message(s) to %s contains %q", addressed, to, containing)
	return Message{}
}

func addressedTo(summary Summary, to string) bool {
	for _, addr := range summary.To {
		if strings.EqualFold(addr.Address, to) {
			return true
		}
	}
	return false
}

// getJSON reads one JSON document from target into into.
func (c *Client) getJSON(target string, into any) error {
	resp, err := c.do(http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		return errs.Wrapf(err, "unable to decode the answer from %s", target)
	}
	return nil
}

// do sends one request and refuses any status outside 2xx, closing the body it refuses.
func (c *Client) do(method, target string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), method, target, body)
	if err != nil {
		return nil, errs.Wrapf(err, "unable to build the request to %s", target)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, errs.Wrapf(err, "unable to reach %s", target)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_ = resp.Body.Close()
		return nil, errs.Errorf("%s %s answered %s", method, target, resp.Status)
	}
	return resp, nil
}
