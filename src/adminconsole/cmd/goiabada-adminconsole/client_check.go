package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/core/errs"
)

// clientTokenSource is what awaitAuthServerAcceptsClient asks for a token: in main, the session
// store's SessionTokenSource, which caches what it obtains, so the first page uses the token the
// check obtained rather than asking again.
type clientTokenSource interface {
	Token(ctx context.Context) (string, error)
}

// awaitAuthServerAcceptsClient asks the auth server for the admin console's own token, the one its
// session store needs on every page, and returns once one is issued. Until #542 nothing asked
// before the console listened, and a console holding a client secret the auth server's database
// does not hold answered every page with 500 while /health answered 200: on Kubernetes a rollout
// replaced working pods with it, and a newly generated secrets file applied to a running
// deployment did exactly that at the next restart.
//
// A refusal is returned at once, since asking again changes nothing: see refusedForGood. Anything
// else is an auth server not answering yet, as on a first start, where both servers start together
// and the auth server migrates and seeds before it listens: it is waited for, retryDelay(attempt)
// apart, with a record per attempt, until ctx is done, when the context's error is returned.
func awaitAuthServerAcceptsClient(ctx context.Context, tokens clientTokenSource, retryDelay func(attempt int) time.Duration) error {
	for attempt := 1; ; attempt++ {
		_, err := tokens.Token(ctx)
		if err == nil {
			return nil
		}
		if refusedForGood(err) {
			return err
		}
		if ctx.Err() != nil {
			return errs.WithStack(ctx.Err())
		}

		delay := retryDelay(attempt)
		slog.InfoContext(ctx, "waiting for the auth server to issue the admin console's token",
			"attempt", attempt,
			"retry_in", delay,
			"error", err)

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errs.WithStack(ctx.Err())
		case <-timer.C:
		}
	}
}

// refusedForGood reports whether err is the token endpoint refusing the request, which asking
// again does not change: an answer in the 4xx range, but for 408 and 429, which ask a client to
// come back later. A connection that fails, a 5xx from the auth server or from a proxy in front of
// it, and an answer the console cannot read are an auth server not answering yet.
func refusedForGood(err error) bool {
	var refusal *oauthclient.TokenEndpointError
	if !errors.As(err, &refusal) {
		return false
	}
	switch refusal.StatusCode {
	case http.StatusRequestTimeout, http.StatusTooManyRequests:
		return false
	}
	return refusal.StatusCode >= 400 && refusal.StatusCode < 500
}

// authServerRetryDelay is how long the console waits before asking the auth server again: one
// second, doubling to a ceiling of ten, so an auth server that comes up in seconds is found at once
// and one that takes minutes, migrating an upgrade, costs a request every ten seconds.
func authServerRetryDelay(attempt int) time.Duration {
	const ceiling = 10 * time.Second
	if attempt < 1 || attempt > 4 {
		return ceiling
	}
	return min(time.Second<<(attempt-1), ceiling)
}

// logClientRefused writes the one record for an auth server refusing the admin console's token
// request, which stops the console. invalid_client is the secret the console holds not being the
// one the auth server's database holds for admin-console-client, and it gets a record of its own
// with the remedy, because it is the refusal a deployment's own secrets cause: a newly generated
// secrets file applied to a running deployment, or a rotation half done. The other refusals are
// the client's provisioning or an address answering for something else, and the error says which,
// the token client's remedy included.
func logClientRefused(err error) {
	var refusal *oauthclient.TokenEndpointError
	if errors.As(err, &refusal) && refusal.ErrorCode == "invalid_client" {
		slog.Error("the auth server does not accept the admin console's client secret, so the admin console cannot start",
			"error", err,
			"remedy", "set GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET to the secret admin-console-client has in the auth server's database: "+
				"the one this deployment was set up with, from your backup of it, or the one last generated for that client")
		return
	}
	slog.Error("the auth server refused the admin console's token request, so the admin console cannot start",
		"error", err)
}
