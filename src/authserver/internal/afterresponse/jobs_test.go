package afterresponse

import (
	"context"
	"log/slog"
	"testing"
	"time"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/core/logging/logtest"
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
	jobs := New()
	ctx, cancel := requestContext("req-detached")

	release := make(chan struct{})
	seen := make(chan context.Context, 1)
	jobs.Go(ctx, func(jobCtx context.Context) {
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
	assert.NoError(t, jobCtx.Err(), "the request's cancellation must not reach the job")
	_, hasDeadline := jobCtx.Deadline()
	assert.False(t, hasDeadline, "the job's only bound is its own work's, not one inherited from the request")
	assert.Equal(t, "req-detached", jobCtx.Value(chimiddleware.RequestIDKey), "the job keeps the request's id")
	assert.True(t, jobs.Wait(5*time.Second))
}

// Go returns at once, whatever the job does: the response is not held for it.
func TestGo_ReturnsBeforeTheJobFinishes(t *testing.T) {
	jobs := New()
	release := make(chan struct{})
	finished := make(chan struct{})

	returned := make(chan struct{})
	go func() {
		jobs.Go(context.Background(), func(context.Context) {
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
	jobs := New()
	release := make(chan struct{})
	finished := make(chan struct{})
	jobs.Go(context.Background(), func(context.Context) {
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

func TestWait_WithNothingInFlightReturnsAtOnce(t *testing.T) {
	assert.True(t, New().Wait(time.Millisecond))
}

// A job that panics is not the request's, so the request's recovery cannot reach it and the panic
// would end the process. It is an Error record on the request's id instead, and Wait still returns.
func TestGo_APanickingJobIsAnErrorRecordAndNotTheEndOfTheProcess(t *testing.T) {
	capture := logtest.CaptureSlog(t)
	jobs := New()
	ctx, cancel := requestContext("req-panic")
	defer cancel()

	jobs.Go(ctx, func(context.Context) { panic("boom") })

	require.True(t, jobs.Wait(5*time.Second), "a panicking job still counts as finished")
	records := capture.Records()
	require.Len(t, records, 1)
	assert.Equal(t, slog.LevelError, records[0].Level)
	assert.Equal(t, "req-panic", records[0].Attrs["request_id"])
	assert.Equal(t, "boom", records[0].Attrs["panic"])
}
