// Package afterresponse runs the work a handler hands off so that its response does not wait for
// it, and lets the server wait for that work on shutdown.
//
// Forgot-password runs the work after its lookup here, after the "link sent" page has gone, so
// every well-formed request answers alike: a request that waited for the code write, the render and
// the SMTP round trip, or answered 500 when the mail failed, only for a real, eligible account
// would tell an observer which addresses are live accounts (#404 decisions 7 and 8). The
// self-service email change sends its notice to the previous address here too, so a mail that fails
// never fails the change (#404 decision 11).
//
// At most maxInFlight jobs run at once. Once the response goes first, one keep-alive connection can
// hand over jobs as fast as it writes requests, each holding up to about 40 seconds of SMTP and a
// database connection for its writes, and with the pool capped that backlog queues in front of
// every sign-in (#485, #394 decision 8).
package afterresponse

import (
	"context"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"
)

// maxInFlight is the number of jobs Go admits at once: three times the server engines' default pool
// of 20, room for a burst of legitimate mail. A constant, because nothing yet says an operator
// needs to tune it (#394 decision 8).
const maxInFlight = 64

// Jobs runs jobs after their responses and counts the ones in flight. The zero value is not used;
// New builds one, and the server holds the one the routes hand to their handlers.
//
// A count and a channel rather than a sync.WaitGroup, because a WaitGroup can only be waited on by
// blocking: Wait had to start a goroutine to do it and race that goroutine against its timer, so
// with nothing in flight a short timeout could win and report jobs left over that did not exist,
// which is how CI saw Wait(time.Millisecond) answer false, and every timeout leaked the goroutine.
// Here nothing in flight is read under the lock and answered without the clock (#404).
type Jobs struct {
	mu       sync.Mutex
	inFlight int
	// idle is closed when inFlight falls to zero, and replaced by an open one when it next rises
	// from zero. It is only meaningful while inFlight is above zero.
	idle chan struct{}
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
//
// With maxInFlight jobs already running, the job is dropped: it never runs and is never counted in
// flight, and one Warn record on the request's id says so. It is not run inline instead, because the
// response must not depend on whether the work ran, which is why it runs after the response (#404
// decisions 7 and 8, #207 decision 4). Under a flood some genuine requests get no mail, the usual
// trade for shedding load (#485).
func (j *Jobs) Go(ctx context.Context, job func(ctx context.Context)) {
	if !j.admit() {
		slog.WarnContext(ctx, "a job to run after its response was dropped, too many in flight",
			"max_in_flight", maxInFlight)
		return
	}
	jobCtx := context.WithoutCancel(ctx)
	go func() {
		defer j.finished()
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
	j.mu.Lock()
	if j.inFlight == 0 {
		j.mu.Unlock()
		return true
	}
	idle := j.idle
	j.mu.Unlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-idle:
		return true
	case <-timer.C:
		return false
	}
}

// admit counts one more job in flight, opening a fresh idle channel when it is the first, and
// reports false, counting nothing, when maxInFlight are already running. The check and the count
// share one lock so concurrent calls cannot both take the last slot.
func (j *Jobs) admit() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.inFlight >= maxInFlight {
		return false
	}
	if j.inFlight == 0 {
		j.idle = make(chan struct{})
	}
	j.inFlight++
	return true
}

// finished counts one job done, closing the idle channel when it was the last.
func (j *Jobs) finished() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.inFlight--
	if j.inFlight == 0 {
		close(j.idle)
	}
}
