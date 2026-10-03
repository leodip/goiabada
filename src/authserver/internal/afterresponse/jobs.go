// Package afterresponse runs the work a handler hands off so that its response does not wait for
// it, and lets the server wait for that work on shutdown.
//
// Forgot-password is why it exists: a request that mailed a link waited for the code write, the
// render and the SMTP round trip while every other outcome returned at once, and a mail failure
// answered 500 only for a real, eligible account, so the response told an observer which addresses
// were live accounts. The work after the lookup now runs here, after the "link sent" page has gone,
// so every well-formed request answers alike (#404 decisions 7 and 8).
package afterresponse

import (
	"context"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"
)

// Jobs runs jobs after their responses and counts the ones in flight. The zero value is not used;
// New builds one, and the server holds the one the routes hand to their handlers.
type Jobs struct {
	running sync.WaitGroup
}

func New() *Jobs {
	return &Jobs{}
}

// Go runs job on a goroutine of its own and returns at once.
//
// The job's context is ctx detached from its cancellation and deadline but keeping its values:
// net/http cancels a request's context the moment its handler returns, which is exactly when a job
// starts, and the values are what carry the request id onto every record and audit entry the job
// writes. The job therefore has no time bound of its own; it owes one through the work it does,
// as the mail sender's dial and conversation deadlines bound a send (#404 decision 8).
//
// A job that panics is no request's, so the request's recovery middleware cannot reach it and the
// panic would end the process. It is recovered here as one Error record on the request's id.
func (j *Jobs) Go(ctx context.Context, job func(ctx context.Context)) {
	jobCtx := context.WithoutCancel(ctx)
	j.running.Add(1)
	go func() {
		defer j.running.Done()
		defer func() {
			if recovered := recover(); recovered != nil {
				slog.ErrorContext(jobCtx, "a job run after its response panicked",
					"panic", recovered,
					"stack", string(debug.Stack()))
			}
		}()
		job(jobCtx)
	}()
}

// Wait waits up to timeout for every job in flight to finish, and reports whether they all did.
//
// The server calls it once its listeners have drained, so no handler is left to start another job
// while it waits (#404 decision 8). A job still running when it gives up is abandoned with the
// process, which loses that request's record and mail as a crash would.
func (j *Jobs) Wait(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		j.running.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}
