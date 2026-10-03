// Package afterresponse runs the work a handler hands off so that its response does not wait for
// it, and lets the server wait for that work on shutdown.
//
// Forgot-password runs the work after its lookup here, after the "link sent" page has gone, so
// every well-formed request answers alike: a request that waited for the code write, the render and
// the SMTP round trip, or answered 500 when the mail failed, only for a real, eligible account
// would tell an observer which addresses are live accounts (#404 decisions 7 and 8). The
// self-service email change sends its notice to the previous address here too, so a mail that fails
// never fails the change (#404 decision 11).
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
func (j *Jobs) Go(ctx context.Context, job func(ctx context.Context)) {
	jobCtx := context.WithoutCancel(ctx)
	j.started()
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

// started counts one more job in flight, opening a fresh idle channel when it is the first.
func (j *Jobs) started() {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.inFlight == 0 {
		j.idle = make(chan struct{})
	}
	j.inFlight++
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
