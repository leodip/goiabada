package afterresponse

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requestContext is a request's context as the handler holds it: carrying chi's request id, and
// cancelled the moment the handler returns, which the test does by calling the cancel it gets.
func requestContext(requestId string) (context.Context, context.CancelFunc) {
	return context.WithCancel(context.WithValue(context.Background(), chimiddleware.RequestIDKey, requestId))
}

// The job outlives its request: the request's cancellation does not reach it, and every value the
// request carried does, so its records and audit entries join the request that started it (#404
// decision 8).
func TestGo_TheJobRunsDetachedFromTheRequestsCancellationButKeepsItsValues(t *testing.T) {
	jobs := New(metrics.NewRegistry())
	ctx, cancel := requestContext("req-detached")

	release := make(chan struct{})
	seen := make(chan context.Context, 1)
	jobs.Go(ctx, ClassRecovery, func(jobCtx context.Context) {
		<-release
		seen <- jobCtx
	})

	// The response has gone: net/http cancels the request's context as the handler returns.
	cancel()
	close(release)

	var jobCtx context.Context
	select {
	case jobCtx = <-seen:
	case <-time.After(5 * time.Second):
		t.Fatal("the job never ran")
	}
	require.NoError(t, jobCtx.Err(), "the request's cancellation must not reach the job")
	_, hasDeadline := jobCtx.Deadline()
	assert.False(t, hasDeadline, "the job's only bound is its own work's, not one inherited from the request")
	assert.Equal(t, "req-detached", jobCtx.Value(chimiddleware.RequestIDKey), "the job keeps the request's id")
	assert.True(t, jobs.Wait(5*time.Second))
}

// Go returns at once, whatever the job does: the response is not held for it.
func TestGo_ReturnsBeforeTheJobFinishes(t *testing.T) {
	jobs := New(metrics.NewRegistry())
	release := make(chan struct{})
	finished := make(chan struct{})

	returned := make(chan struct{})
	go func() {
		jobs.Go(context.Background(), ClassRecovery, func(context.Context) {
			<-release
			close(finished)
		})
		close(returned)
	}()

	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("Go waited for the job")
	}
	select {
	case <-finished:
		t.Fatal("the job finished before it was released")
	default:
	}
	close(release)
	assert.True(t, jobs.Wait(5*time.Second))
}

// Shutdown waits for a job in flight, and for no longer than it is given.
func TestWait_WaitsForTheJobsInFlight(t *testing.T) {
	jobs := New(metrics.NewRegistry())
	release := make(chan struct{})
	finished := make(chan struct{})
	jobs.Go(context.Background(), ClassRecovery, func(context.Context) {
		<-release
		close(finished)
	})

	assert.False(t, jobs.Wait(50*time.Millisecond), "a job still running is reported as not finished")

	waited := make(chan bool, 1)
	go func() { waited <- jobs.Wait(5 * time.Second) }()
	select {
	case <-waited:
		t.Fatal("Wait returned while the job was still running")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)
	select {
	case ok := <-waited:
		assert.True(t, ok)
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return once the job finished")
	}
	select {
	case <-finished:
	default:
		t.Fatal("Wait returned before the job finished")
	}
}

// Nothing in flight is answered without the clock, so even a zero timeout reports it, both before
// any job has run and after every one has finished. It was a 1 ms timeout raced against a
// goroutine, which a busy CI runner lost (#404).
func TestWait_WithNothingInFlightReturnsAtOnce(t *testing.T) {
	jobs := New(metrics.NewRegistry())
	assert.True(t, jobs.Wait(0), "no job has run")

	done := make(chan struct{})
	jobs.Go(context.Background(), ClassRecovery, func(context.Context) { close(done) })
	<-done
	require.True(t, jobs.Wait(5*time.Second), "the job must finish")
	assert.True(t, jobs.Wait(0), "every job has finished")
}

// A job still running when the timeout passes is reported, and a later Wait sees it finish: the
// idle channel a first job opens serves every Wait until the last one closes it, and the next job
// opens a fresh one.
func TestWait_AJobStillRunningAtTheTimeoutIsReported(t *testing.T) {
	jobs := New(metrics.NewRegistry())
	release := make(chan struct{})
	jobs.Go(context.Background(), ClassRecovery, func(context.Context) { <-release })

	assert.False(t, jobs.Wait(0), "the job is still running")
	assert.False(t, jobs.Wait(10*time.Millisecond), "the job is still running")

	close(release)
	require.True(t, jobs.Wait(5*time.Second), "the job finished")

	again := make(chan struct{})
	jobs.Go(context.Background(), ClassRecovery, func(context.Context) { <-again })
	assert.False(t, jobs.Wait(0), "a job started after the last one finished is in flight")
	close(again)
	assert.True(t, jobs.Wait(5*time.Second))
}

// A job that panics is not the request's, so the request's recovery cannot reach it and the panic
// would end the process. It is an Error record on the request's id instead, and Wait still returns.
func TestGo_APanickingJobIsAnErrorRecordAndNotTheEndOfTheProcess(t *testing.T) {
	capture := logtest.CaptureSlog(t)
	jobs := New(metrics.NewRegistry())
	ctx, cancel := requestContext("req-panic")
	defer cancel()

	jobs.Go(ctx, ClassRecovery, func(context.Context) { panic("boom") })

	require.True(t, jobs.Wait(5*time.Second), "a panicking job still counts as finished")
	records := capture.Records()
	require.Len(t, records, 1)
	assert.Equal(t, slog.LevelError, records[0].Level)
	assert.Equal(t, "req-panic", records[0].Attrs["request_id"])
	assert.Equal(t, "boom", records[0].Attrs["panic"])
}

// fillToTheCap starts 64 jobs of class, the cap per class #394 decision 8 sets, each blocked until
// release is closed, and returns once every one of them is running.
func fillToTheCap(t *testing.T, jobs *Jobs, class Class, release <-chan struct{}) {
	t.Helper()
	running := make(chan struct{}, 64)
	for range 64 {
		jobs.Go(context.Background(), class, func(context.Context) {
			running <- struct{}{}
			<-release
		})
	}
	for i := range 64 {
		select {
		case <-running:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of the 64 jobs under the cap ran", i)
		}
	}
}

// warnings returns the Warn records captured so far.
func warnings(capture *logtest.SlogCapture) []logtest.CapturedRecord {
	var found []logtest.CapturedRecord
	for _, record := range capture.Records() {
		if record.Level == slog.LevelWarn {
			found = append(found, record)
		}
	}
	return found
}

// With 64 jobs in flight the next one is dropped: Go returns at once without running it, inline or
// later, and records one Warn on the request's id. Running it inline would make the response depend
// on whether the work ran, which is what running it after the response exists to prevent (#485,
// #404 decisions 7 and 8).
func TestGo_AJobPastTheCapIsDroppedWithOneWarnRecord(t *testing.T) {
	capture := logtest.CaptureSlog(t)
	jobs := New(metrics.NewRegistry())
	release := make(chan struct{})
	fillToTheCap(t, jobs, ClassRecovery, release)
	require.Empty(t, warnings(capture), "the 64 jobs under the cap are all admitted")

	ctx, cancel := requestContext("req-dropped")
	defer cancel()
	var ran atomic.Bool
	returned := make(chan struct{})
	go func() {
		jobs.Go(ctx, ClassRecovery, func(context.Context) {
			ran.Store(true)
			<-release
		})
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("Go ran the dropped job inline")
	}

	close(release)
	require.True(t, jobs.Wait(5*time.Second))
	assert.False(t, ran.Load(), "a dropped job never runs")

	dropped := warnings(capture)
	require.Len(t, dropped, 1)
	assert.Equal(t, "req-dropped", dropped[0].Attrs["request_id"])
	assert.Equal(t, "recovery", dropped[0].Attrs["class"], "the record names the budget that was full")
}

// Each class has a budget of its own: with recovery's 64 slots full, a registration job and an
// account notice are admitted and run, and only the next recovery job is dropped. The notice is the
// one that matters: without this, whoever held a stolen session could fill the budget through the
// public forgot-password form, then change the address, and the mail warning the victim was the
// one dropped (#394 review).
func TestGo_AFullClassTakesNoSlotFromAnotherClass(t *testing.T) {
	capture := logtest.CaptureSlog(t)
	jobs := New(metrics.NewRegistry())
	release := make(chan struct{})
	fillToTheCap(t, jobs, ClassRecovery, release)

	ran := make(chan Class, 2)
	for _, class := range []Class{ClassRegistration, ClassAccountNotice} {
		jobs.Go(context.Background(), class, func(context.Context) { ran <- class })
	}
	var seen []Class
	for range 2 {
		select {
		case class := <-ran:
			seen = append(seen, class)
		case <-time.After(5 * time.Second):
			t.Fatal("a job of another class was not run while recovery's budget was full")
		}
	}
	assert.ElementsMatch(t, []Class{ClassRegistration, ClassAccountNotice}, seen)
	assert.Empty(t, warnings(capture), "the other classes' budgets are untouched")

	jobs.Go(context.Background(), ClassRecovery, func(context.Context) {})
	dropped := warnings(capture)
	require.Len(t, dropped, 1, "recovery's own budget still holds")
	assert.Equal(t, "recovery", dropped[0].Attrs["class"])

	close(release)
	assert.True(t, jobs.Wait(5*time.Second))
}

// Wait waits for every class: with nothing of recovery's in flight, a notice still running holds it.
func TestWait_WaitsForEveryClass(t *testing.T) {
	jobs := New(metrics.NewRegistry())
	release := make(chan struct{})
	jobs.Go(context.Background(), ClassAccountNotice, func(context.Context) { <-release })
	assert.False(t, jobs.Wait(0), "the notice is still running")
	close(release)
	assert.True(t, jobs.Wait(5*time.Second))
}

// A dropped job is never counted in flight: Wait answers for the 64 admitted jobs alone, at once
// when they have finished, though the dropped one never will.
func TestWait_WaitsForAdmittedJobsOnly(t *testing.T) {
	logtest.CaptureSlog(t)
	jobs := New(metrics.NewRegistry())
	release := make(chan struct{})
	fillToTheCap(t, jobs, ClassRecovery, release)

	never := make(chan struct{})
	defer close(never)
	returned := make(chan struct{})
	go func() {
		jobs.Go(context.Background(), ClassRecovery, func(context.Context) { <-never })
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("Go ran the dropped job inline")
	}

	assert.False(t, jobs.Wait(0), "the 64 admitted jobs are still running")
	close(release)
	require.True(t, jobs.Wait(5*time.Second), "the admitted jobs finished, and the dropped one is not waited for")
	assert.True(t, jobs.Wait(0), "nothing is left in flight")
}

// A job that finishes gives its slot back: once 64 have finished, 64 more are admitted and only the
// next is dropped.
func TestGo_AFinishedJobReleasesItsSlot(t *testing.T) {
	capture := logtest.CaptureSlog(t)
	jobs := New(metrics.NewRegistry())
	first := make(chan struct{})
	fillToTheCap(t, jobs, ClassRecovery, first)
	close(first)
	require.True(t, jobs.Wait(5*time.Second))

	second := make(chan struct{})
	fillToTheCap(t, jobs, ClassRecovery, second)
	assert.Empty(t, warnings(capture), "every slot the first 64 held was given back")

	jobs.Go(context.Background(), ClassRecovery, func(context.Context) {})
	assert.Len(t, warnings(capture), 1, "the cap still holds once the slots are taken again")
	close(second)
	assert.True(t, jobs.Wait(5*time.Second))
}

// A job that panics gives its slot back too, so a run of panics cannot shrink the cap until every
// later job is dropped.
func TestGo_APanickingJobReleasesItsSlot(t *testing.T) {
	capture := logtest.CaptureSlog(t)
	jobs := New(metrics.NewRegistry())
	for range 64 {
		jobs.Go(context.Background(), ClassRecovery, func(context.Context) { panic("boom") })
	}
	require.True(t, jobs.Wait(5*time.Second))

	release := make(chan struct{})
	fillToTheCap(t, jobs, ClassRecovery, release)
	assert.Empty(t, warnings(capture), "every slot a panicking job held was given back")
	close(release)
	assert.True(t, jobs.Wait(5*time.Second))
}

// The cap holds under concurrent calls: of 200 jobs handed over at once while none finishes,
// exactly 64 run and the other 136 are dropped, one Warn record each.
func TestGo_ConcurrentCallsAdmitExactlyTheCap(t *testing.T) {
	capture := logtest.CaptureSlog(t)
	jobs := New(metrics.NewRegistry())
	release := make(chan struct{})
	var ran atomic.Int32

	var callers sync.WaitGroup
	for range 200 {
		callers.Add(1)
		go func() {
			defer callers.Done()
			jobs.Go(context.Background(), ClassRecovery, func(context.Context) {
				ran.Add(1)
				<-release
			})
		}()
	}
	allReturned := make(chan struct{})
	go func() {
		callers.Wait()
		close(allReturned)
	}()
	select {
	case <-allReturned:
	case <-time.After(5 * time.Second):
		t.Fatal("Go ran a dropped job inline")
	}
	close(release)
	require.True(t, jobs.Wait(5*time.Second))

	assert.Equal(t, int32(64), ran.Load())
	assert.Len(t, warnings(capture), 136)
}
