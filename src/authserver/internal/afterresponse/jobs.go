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
// At most maxInFlight jobs of each class run at once. Once the response goes first, one keep-alive
// connection can hand over jobs as fast as it writes requests, each holding up to about 40 seconds
// of SMTP and a database connection for its writes, and with the pool capped that backlog queues in
// front of every sign-in (#485, #394 decision 8). The budget is per class rather than one for all,
// because two of the three callers are public forms and the third is the notice that tells a user
// their address was changed: with one shared budget, whoever held a stolen session could fill it
// through the forgot-password form at no cost, then change the address, and the one mail that
// would have warned the victim was the one dropped (#394 review).
package afterresponse

import (
	"context"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"github.com/leodip/goiabada/core/metrics"
)

// maxInFlight is the number of jobs of one class Go admits at once: three times the server engines'
// default pool of 20, room for a burst of legitimate mail. A constant, because nothing yet says an
// operator needs to tune it (#394 decision 8).
const maxInFlight = 64

// Class is the kind of work a job does, and names the budget it is admitted against. Each class has
// its own maxInFlight, so a flood of one kind of request fills that kind's budget and no other's.
// A new caller declares a class here rather than borrowing one, because sharing a budget is what
// lets one caller's flood drop another's mail (#394 review).
type Class string

const (
	// ClassRecovery is forgot-password's code store, audit record and mail: public, unauthenticated.
	ClassRecovery Class = "recovery"
	// ClassRegistration is self-registration's pre-registration write, audit record and mail:
	// public, unauthenticated, reachable while self-registration is enabled.
	ClassRegistration Class = "registration"
	// ClassAccountNotice is the self-service email change's notice to the previous address: behind a
	// bearer token, and the one job whose loss benefits whoever holds a stolen session.
	ClassAccountNotice Class = "account_notice"
)

// classes is every class declared above, the closed set the metrics' class label takes (#400
// decision 4). A class missing from it would be reported as other.
var classes = []Class{ClassRecovery, ClassRegistration, ClassAccountNotice}

// Jobs runs jobs after their responses and counts the ones in flight. The zero value is not used;
// New builds one, and the server holds the one the routes hand to their handlers.
//
// A count and a channel rather than a sync.WaitGroup, because a WaitGroup can only be waited on by
// blocking: Wait had to start a goroutine to do it and race that goroutine against its timer, so
// with nothing in flight a short timeout could win and report jobs left over that did not exist,
// which is how CI saw Wait(time.Millisecond) answer false, and every timeout leaked the goroutine.
// Here nothing in flight is read under the lock and answered without the clock (#404).
type Jobs struct {
	mu sync.Mutex
	// inFlight counts the jobs running of each class, and total is their sum, read by Wait.
	inFlight map[Class]int
	total    int
	// idle is closed when total falls to zero, and replaced by an open one when it next rises from
	// zero. It is only meaningful while total is above zero.
	idle chan struct{}

	// dropped counts the jobs Go dropped at their class's cap, by class (#400 decision 5).
	dropped *metrics.Counter
}

// New builds the jobs and registers their two families on reg: the jobs in flight by class, read
// from the count Go admits against at every scrape, and the jobs dropped by class.
func New(reg *metrics.Registry) *Jobs {
	names := make([]string, len(classes))
	for i, class := range classes {
		names[i] = string(class)
	}

	j := &Jobs{inFlight: map[Class]int{}}
	reg.GaugeVecFunc("goiabada_after_response_jobs_in_flight",
		"Jobs handed off to run after their responses that are running now, by class.",
		j.inFlightSamples,
		metrics.Enum("class", names...))
	j.dropped = reg.Counter("goiabada_after_response_jobs_dropped_total",
		"Jobs handed off to run after their responses that were dropped because their class was at its cap, by class.",
		metrics.Enum("class", names...))
	return j
}

// inFlightSamples reads the jobs in flight of every class, under the lock admit counts them under.
func (j *Jobs) inFlightSamples() []metrics.Sample {
	j.mu.Lock()
	defer j.mu.Unlock()
	samples := make([]metrics.Sample, len(classes))
	for i, class := range classes {
		samples[i] = metrics.Sample{Value: float64(j.inFlight[class]), LabelValues: []string{string(class)}}
	}
	return samples
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
// With maxInFlight jobs of the same class already running, the job is dropped: it never runs and
// is never counted in flight, and one Warn record on the request's id says so. It is not run inline
// instead, because the response must not depend on whether the work ran, which is why it runs
// after the response (#404 decisions 7 and 8, #207 decision 4). Under a flood some genuine
// requests of that class get no mail, the usual trade for shedding load, and jobs of every other
// class are admitted as if the flood were not there (#485, #394 review).
func (j *Jobs) Go(ctx context.Context, class Class, job func(ctx context.Context)) {
	if !j.admit(class) {
		j.dropped.Inc(string(class))
		slog.WarnContext(ctx, "a job to run after its response was dropped, too many in flight",
			"class", string(class),
			"max_in_flight", maxInFlight)
		return
	}
	jobCtx := context.WithoutCancel(ctx)
	go func() {
		defer j.finished(class)
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
	if j.total == 0 {
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

// admit counts one more job of class in flight, opening a fresh idle channel when it is the first
// of any class, and reports false, counting nothing, when maxInFlight of that class are already
// running. The check and the count share one lock so concurrent calls cannot both take the last
// slot.
func (j *Jobs) admit(class Class) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.inFlight[class] >= maxInFlight {
		return false
	}
	if j.total == 0 {
		j.idle = make(chan struct{})
	}
	j.inFlight[class]++
	j.total++
	return true
}

// finished counts one job of class done, closing the idle channel when it was the last of any
// class.
func (j *Jobs) finished(class Class) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.inFlight[class]--
	j.total--
	if j.total == 0 {
		close(j.idle)
	}
}
