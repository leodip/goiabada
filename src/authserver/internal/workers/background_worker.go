package workers

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/leodip/goiabada/core/data"
)

type Worker struct {
	database data.Database
	stopChan chan struct{}
	wg       sync.WaitGroup
}

func NewWorker(database data.Database) *Worker {
	return &Worker{
		database: database,
		stopChan: make(chan struct{}),
	}
}

func (w *Worker) Start() {
	w.wg.Add(1)
	go w.run()
	slog.Info("background worker service started")
}

func (w *Worker) Stop() {
	close(w.stopChan)
	w.wg.Wait()
	slog.Info("background worker service stopped")
}

func (w *Worker) run() {
	defer w.wg.Done()

	// wait 10 seconds
	time.Sleep(10 * time.Second)

	w.performTask()

	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			w.performTask()
		case <-w.stopChan:
			return
		}
	}
}

// performTask executes the main worker task
func (w *Worker) performTask() {
	slog.Info("worker task started")

	err := w.database.DeleteExpiredOrRevokedRefreshTokens(nil)
	if err != nil {
		slog.Error(fmt.Sprintf("error deleting expired or revoked refresh tokens: %v", err))
	} else {
		slog.Info("deleted expired or revoked refresh tokens")
	}

	err = w.database.DeleteUsedCodesWithoutRefreshTokens(nil)
	if err != nil {
		slog.Error(fmt.Sprintf("error deleting used codes without refresh tokens: %v", err))
	} else {
		slog.Info("deleted used codes without refresh tokens")
	}

	settings, err := w.database.GetSettingsById(nil, 1)
	if err != nil {
		slog.Error(fmt.Sprintf("error getting settings: %v", err))
		return
	}

	err = w.database.DeleteIdleSessions(nil, time.Duration(settings.UserSessionIdleTimeoutInSeconds)*time.Second)
	if err != nil {
		slog.Error(fmt.Sprintf("error deleting idle sessions: %v", err))
	} else {
		slog.Info(fmt.Sprintf("deleted idle sessions (idle timeout: %d seconds)", settings.UserSessionIdleTimeoutInSeconds))
	}

	err = w.database.DeleteExpiredSessions(nil, time.Duration(settings.UserSessionMaxLifetimeInSeconds)*time.Second)
	if err != nil {
		slog.Error(fmt.Sprintf("error deleting expired sessions: %v", err))
	} else {
		slog.Info(fmt.Sprintf("deleted expired sessions (max lifetime: %d seconds)", settings.UserSessionMaxLifetimeInSeconds))
	}

	slog.Info("worker task completed")
}
