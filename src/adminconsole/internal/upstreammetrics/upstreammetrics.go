// Package upstreammetrics records, on the metrics listener, the admin console's calls to the auth
// server (#400 decision 6): goiabada_upstream_requests_total by target and status, and
// goiabada_upstream_request_duration_seconds by target. The auth server is the console's failure
// mode, so these are what show whether it is slow or failing as the console sees it.
//
// target names which of the console's five HTTP clients made the call, never the API method or the
// path: each client wraps its own *http.Client under its own Target, so the label is decided where
// the client is built and nothing taken from a request reaches it (#400 decision 4).
package upstreammetrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/leodip/goiabada/core/metrics"
)

// Target is which of the console's HTTP clients made a call to the auth server.
type Target string

// The five clients, each the target its calls are recorded under.
const (
	// AdminAPI is apiclient's executor, behind every AuthServerClient method.
	AdminAPI Target = "admin_api"
	// Settings is publicsettings' client of /api/public/settings.
	Settings Target = "settings"
	// Token is oauthclient's token client: the sign-in's exchange, the refresh and the client
	// credentials grant the session backend's token comes from.
	Token Target = "token"
	// JWKS is oauthclient's fetch of /certs.
	JWKS Target = "jwks"
	// Sessions is sessionbackend's calls to the browser-session endpoint.
	Sessions Target = "sessions"
)

// targets is the target label's set.
var targets = []Target{AdminAPI, Settings, Token, JWKS, Sessions}

// transportError is the status a call that received no response is recorded under: a connection
// refused, a reset, a timeout.
const transportError = "error"

// Recorder records the console's calls to the auth server. A nil *Recorder records nothing, which
// is what a test about something else passes; main always passes the one it registered.
type Recorder struct {
	requests *metrics.Counter
	duration *metrics.Histogram
}

// Register registers the two upstream families on reg and returns the recorder that records in
// them.
func Register(reg *metrics.Registry) *Recorder {
	names := make([]string, len(targets))
	for i, t := range targets {
		names[i] = string(t)
	}
	target := metrics.Enum("target", names...)
	status := metrics.Described("status", "the response's status code, or `error`", statuses()...)

	return &Recorder{
		requests: reg.Counter("goiabada_upstream_requests_total",
			"Calls the admin console made to the auth server, by the client that made them and the status code, or error when no response arrived.",
			target, status),
		duration: reg.Histogram("goiabada_upstream_request_duration_seconds",
			"How long the admin console's calls to the auth server took until the response headers arrived, by the client that made them.",
			metrics.DurationBuckets(), target),
	}
}

// Client returns a copy of client whose every call is recorded under target, client itself
// untouched; a nil recorder returns client as it is. The copy keeps client's timeout, redirect
// policy and cookie jar, and sends through client's own transport, or the default one when it has
// none.
func (r *Recorder) Client(target Target, client *http.Client) *http.Client {
	if r == nil {
		return client
	}
	next := client.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	recorded := *client
	recorded.Transport = &transport{next: next, target: string(target), recorder: r}
	return &recorded
}

// transport records each round trip it sends through next.
type transport struct {
	next     http.RoundTripper
	target   string
	recorder *Recorder
}

// RoundTrip sends req and records it once, when the response headers arrive or the call fails.
// The duration is to the headers, which is what RoundTrip waits for; a body read after it is the
// caller's. A retry its caller makes is a call of its own, and is recorded as one.
func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	started := time.Now()
	resp, err := t.next.RoundTrip(req)
	status := transportError
	if err == nil {
		status = strconv.Itoa(resp.StatusCode)
	}
	t.recorder.requests.Inc(t.target, status)
	t.recorder.duration.Observe(time.Since(started).Seconds(), t.target)
	return resp, err
}

// statuses is the status label's set: every three-digit code from 100 to 599, the one the auth
// server chose to answer with, and error. The codes are core/metrics' HTTP status set, which this
// module cannot name because it is unexported there.
func statuses() []string {
	values := make([]string, 0, 501)
	for code := 100; code <= 599; code++ {
		values = append(values, strconv.Itoa(code))
	}
	return append(values, transportError)
}
