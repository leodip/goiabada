package afterresponse

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/metrics"
)

// The after-response jobs on the metrics listener (#400 decision 5): how many of each class are in
// flight, read at the scrape, and how many each class has dropped at its cap.

// jobSamples answers the sample lines of the two after-response families in reg's exposition.
func jobSamples(t *testing.T, reg *metrics.Registry) []string {
	t.Helper()

	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var samples []string
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if strings.HasPrefix(line, "goiabada_after_response_jobs_") {
			samples = append(samples, line)
		}
	}
	return samples
}

func TestJobs_TheScrapeReportsTheJobsInFlightAndDroppedByClass(t *testing.T) {
	reg := metrics.NewRegistry()
	jobs := New(reg)

	// Before any job, every class reads zero in flight and zero dropped. Series are written in the
	// order of their label values. The dropped series exist before the first drop, because
	// increase() reads nothing over a window in which a series first appears, so a class whose
	// series appeared only at its first drop raised no GoiabadaAfterResponseJobsDropped alert for it.
	assert.Equal(t, []string{
		`goiabada_after_response_jobs_dropped_total{class="account_notice"} 0`,
		`goiabada_after_response_jobs_dropped_total{class="recovery"} 0`,
		`goiabada_after_response_jobs_dropped_total{class="registration"} 0`,
		`goiabada_after_response_jobs_in_flight{class="account_notice"} 0`,
		`goiabada_after_response_jobs_in_flight{class="recovery"} 0`,
		`goiabada_after_response_jobs_in_flight{class="registration"} 0`,
	}, jobSamples(t, reg))

	// Recovery at its cap, one registration job running, and two recovery jobs past the cap.
	release := make(chan struct{})
	fillToTheCap(t, jobs, ClassRecovery, release)
	registrationRunning := make(chan struct{})
	jobs.Go(context.Background(), ClassRegistration, func(context.Context) {
		close(registrationRunning)
		<-release
	})
	<-registrationRunning
	for range 2 {
		jobs.Go(context.Background(), ClassRecovery, func(context.Context) { t.Error("a dropped job ran") })
	}

	assert.Equal(t, []string{
		`goiabada_after_response_jobs_dropped_total{class="account_notice"} 0`,
		`goiabada_after_response_jobs_dropped_total{class="recovery"} 2`,
		`goiabada_after_response_jobs_dropped_total{class="registration"} 0`,
		`goiabada_after_response_jobs_in_flight{class="account_notice"} 0`,
		`goiabada_after_response_jobs_in_flight{class="recovery"} 64`,
		`goiabada_after_response_jobs_in_flight{class="registration"} 1`,
	}, jobSamples(t, reg))

	// Once they finish, nothing is in flight, and what was dropped stays counted.
	close(release)
	require.True(t, jobs.Wait(5*time.Second))
	assert.Equal(t, []string{
		`goiabada_after_response_jobs_dropped_total{class="account_notice"} 0`,
		`goiabada_after_response_jobs_dropped_total{class="recovery"} 2`,
		`goiabada_after_response_jobs_dropped_total{class="registration"} 0`,
		`goiabada_after_response_jobs_in_flight{class="account_notice"} 0`,
		`goiabada_after_response_jobs_in_flight{class="recovery"} 0`,
		`goiabada_after_response_jobs_in_flight{class="registration"} 0`,
	}, jobSamples(t, reg))
}
