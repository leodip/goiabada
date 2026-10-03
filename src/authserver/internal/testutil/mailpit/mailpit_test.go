package mailpit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/guard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Seam 6. The client against an httptest.Server that answers the three endpoints the way Mailpit
// does, so every failure path the dev container's Mailpit never takes is reached here, and
// AssertEmailSent's is driven under guard.Run, which reproduces what Fatalf means (#431).

// fakeMailpit serves a fixed set of messages and records what it was asked for.
type fakeMailpit struct {
	mu       sync.Mutex
	messages []Message
	fetched  []string
	deleted  []string
	// listStatus and deleteStatus replace the answer when set; listBody replaces the list's body.
	listStatus   int
	listBody     string
	messageBody  string
	deleteStatus int
}

func (f *fakeMailpit) start(t *testing.T) *Client {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/messages", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		assert.Equal(t, "200", r.URL.Query().Get("limit"))
		if f.listStatus != 0 {
			w.WriteHeader(f.listStatus)
			return
		}
		if f.listBody != "" {
			_, _ = w.Write([]byte(f.listBody))
			return
		}
		summaries := make([]Summary, 0, len(f.messages))
		for _, m := range f.messages {
			summaries = append(summaries, Summary{ID: m.ID, MessageID: m.MessageID, From: m.From, To: m.To, Subject: m.Subject, Created: m.Created})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"total": len(summaries), "messages": summaries})
	})
	mux.HandleFunc("GET /api/v1/message/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		id := r.PathValue("id")
		f.fetched = append(f.fetched, id)
		if f.messageBody != "" {
			_, _ = w.Write([]byte(f.messageBody))
			return
		}
		for _, m := range f.messages {
			if m.ID == id {
				_ = json.NewEncoder(w).Encode(m)
				return
			}
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("DELETE /api/v1/messages", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		var body struct {
			IDs []string `json:"IDs"`
		}
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		if f.deleteStatus != 0 {
			w.WriteHeader(f.deleteStatus)
			return
		}
		f.deleted = append(f.deleted, body.IDs...)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return New(server.URL + "/")
}

func (f *fakeMailpit) record() (fetched, deleted []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.fetched...), append([]string(nil), f.deleted...)
}

func fixtureMessage(id, to, html string) Message {
	return Message{
		ID:        id,
		MessageID: id + "@example.com",
		From:      Address{Name: "Goiabada", Address: "noreply@example.com"},
		To:        []Address{{Address: to}},
		Subject:   "subject " + id,
		Created:   time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC),
		HTML:      html,
	}
}

func TestAssertEmailSent_Match(t *testing.T) {
	f := &fakeMailpit{messages: []Message{
		fixtureMessage("other", "someone@example.com", "<p>the text</p>"),
		fixtureMessage("wrong-body", "Rcpt@Example.com", "<p>something else</p>"),
		fixtureMessage("match", "Rcpt@Example.com", "<p>the text</p>"),
		fixtureMessage("older-match", "rcpt@example.com", "<p>the text</p>"),
	}}
	client := f.start(t)

	var got Message
	report := guard.Run(func(r guard.Reporter) {
		got = client.AssertEmailSent(r, "rcpt@example.com", "the text")
	})

	require.False(t, report.Failed(), report.Text())
	assert.Equal(t, "match", got.ID, "the recipient matches case-insensitively and the first match wins")
	assert.Equal(t, "Goiabada", got.From.Name)
	assert.Equal(t, "match@example.com", got.MessageID)

	fetched, deleted := f.record()
	assert.Equal(t, []string{"wrong-body", "match"}, fetched, "a message to someone else is never fetched, and nothing after the match is")
	assert.Equal(t, []string{"match"}, deleted, "the match is deleted so the next test does not read it back")
}

func TestAssertEmailSent_TextBodyMatches(t *testing.T) {
	plain := fixtureMessage("plain", "rcpt@example.com", "")
	plain.Text = "the text"
	f := &fakeMailpit{messages: []Message{plain}}
	client := f.start(t)

	var got Message
	report := guard.Run(func(r guard.Reporter) {
		got = client.AssertEmailSent(r, "rcpt@example.com", "the text")
	})

	require.False(t, report.Failed(), report.Text())
	assert.Equal(t, "plain", got.ID)
}

func TestAssertEmailSent_RecipientMismatch(t *testing.T) {
	f := &fakeMailpit{messages: []Message{fixtureMessage("other", "someone@example.com", "<p>the text</p>")}}
	client := f.start(t)

	reachedEnd := false
	report := guard.Run(func(r guard.Reporter) {
		client.AssertEmailSent(r, "rcpt@example.com", "the text")
		reachedEnd = true
	})

	assert.True(t, report.Stopped, "a miss is fatal")
	assert.False(t, reachedEnd, "the caller never sees the zero Message")
	assert.Equal(t, "no message to rcpt@example.com among the 1 newest Mailpit holds", report.Fatal)
	fetched, deleted := f.record()
	assert.Empty(t, fetched)
	assert.Empty(t, deleted)
}

func TestAssertEmailSent_BodyMismatch(t *testing.T) {
	f := &fakeMailpit{messages: []Message{
		fixtureMessage("a", "rcpt@example.com", "<p>something else</p>"),
		fixtureMessage("b", "rcpt@example.com", "<p>nor this</p>"),
	}}
	client := f.start(t)

	report := guard.Run(func(r guard.Reporter) {
		client.AssertEmailSent(r, "rcpt@example.com", "the text")
	})

	assert.True(t, report.Stopped)
	assert.Equal(t, `none of the 2 message(s) to rcpt@example.com contains "the text"`, report.Fatal)
	_, deleted := f.record()
	assert.Empty(t, deleted, "nothing that did not match is deleted")
}

func TestClient_NonSuccessStatus(t *testing.T) {
	f := &fakeMailpit{listStatus: http.StatusServiceUnavailable}
	client := f.start(t)

	_, err := client.List()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to list the messages Mailpit holds")
	assert.Contains(t, err.Error(), "503 Service Unavailable")

	report := guard.Run(func(r guard.Reporter) {
		client.AssertEmailSent(r, "rcpt@example.com", "the text")
	})
	assert.True(t, report.Stopped)
	assert.Contains(t, report.Fatal, "503 Service Unavailable")

	_, err = client.Message("absent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to read message absent from Mailpit")
	assert.Contains(t, err.Error(), "404 Not Found")
}

func TestClient_MalformedJSON(t *testing.T) {
	f := &fakeMailpit{listBody: `{"messages": [`}
	client := f.start(t)

	_, err := client.List()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to decode the answer from")

	f = &fakeMailpit{messages: []Message{fixtureMessage("m", "rcpt@example.com", "x")}, messageBody: `{"ID": 7}`}
	client = f.start(t)

	_, err = client.Message("m")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to read message m from Mailpit")
	assert.Contains(t, err.Error(), "unable to decode the answer from")

	report := guard.Run(func(r guard.Reporter) {
		client.AssertEmailSent(r, "rcpt@example.com", "x")
	})
	assert.True(t, report.Stopped, "a message that cannot be read is fatal, not skipped")
	assert.Contains(t, report.Fatal, "unable to read message m from Mailpit")
}

func TestAssertEmailSent_FailedDeleteIsReported(t *testing.T) {
	f := &fakeMailpit{
		messages:     []Message{fixtureMessage("match", "rcpt@example.com", "<p>the text</p>")},
		deleteStatus: http.StatusInternalServerError,
	}
	client := f.start(t)

	var got Message
	report := guard.Run(func(r guard.Reporter) {
		got = client.AssertEmailSent(r, "rcpt@example.com", "the text")
	})

	assert.False(t, report.Stopped, "the message was found, so the caller still gets it")
	assert.Equal(t, "match", got.ID)
	require.Len(t, report.Errors, 1)
	assert.Contains(t, report.Errors[0], "unable to delete message match from Mailpit")
	assert.Contains(t, report.Errors[0], "500 Internal Server Error")
}

func TestNew_BoundsEveryRequestByTenSeconds(t *testing.T) {
	assert.Equal(t, 10*time.Second, New("http://mailpit:8025").http.Timeout)
}

// A Mailpit that accepts the connection and never answers. The client's own timeout is what ends
// the request, and the test holds a bound of its own so that a client without one fails here
// rather than hanging the tier.
func TestClient_StalledServerTimesOut(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	// Cleanups run last-registered first, so the handler is released before Close waits on it.
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })

	client := newClient(server.URL, 100*time.Millisecond)

	done := make(chan error, 1)
	go func() {
		_, err := client.List()
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unable to reach")
		assert.True(t, strings.Contains(err.Error(), "Client.Timeout") || strings.Contains(err.Error(), "deadline exceeded"),
			"the request ended on the client's timeout: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("the request outlived its 100ms timeout by five seconds")
	}
}
