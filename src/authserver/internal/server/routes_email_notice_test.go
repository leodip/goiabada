package server

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/afterresponse"
	"github.com/leodip/goiabada/authserver/internal/config"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestInitRoutes_EmailChangeNoticeIsSelfServiceOnly is the boundary of #404 decision 11 at the
// routes: the notice to the previous address goes out for a self-service change, and an
// administrator changing another user's address, which needs no password, sends nothing to either
// address even with mail on.
//
// The notice is sent after the response, so its absence means nothing until every job the request
// could have started has finished. Each case therefore waits on the server's own afterresponse.Jobs,
// the runner initRoutes hands the handlers, before it reads the capture: a job that sends dials the
// capture and completes its conversation before it returns, so whatever it sent is recorded by then.
// The self-service case is the control that the capture and the settings reach the sender at all.
func TestInitRoutes_EmailChangeNoticeIsSelfServiceOnly(t *testing.T) {
	const (
		previousEmail = "previous@example.com"
		newEmail      = "new@example.com"
		password      = "the account's real password"
	)

	passwordHash, err := passwordhash.Hash(password)
	require.NoError(t, err)

	newServer := noticeTestServer
	request := noticeTestRequest

	t.Run("a self-service change notifies the previous address", func(t *testing.T) {
		capture := newSMTPCapture(t)

		database := mocks_data.NewDatabase(t)
		database.On("GetUserBySubject", mock.Anything, mock.Anything, routesTestSubject).Return(&record.User{
			Id:            1,
			Enabled:       true,
			Subject:       routesTestSubject,
			Email:         previousEmail,
			EmailVerified: true,
			PasswordHash:  passwordHash,
		}, nil)
		database.On("GetUserByEmail", mock.Anything, mock.Anything, newEmail).Return((*record.User)(nil), nil)
		database.On("TrySetUserEmail", mock.Anything, mock.Anything, int64(1), previousEmail, true, newEmail).Return(true, nil).Once()
		s := newServer(t, database)

		body := `{"email":"` + newEmail + `","currentPassword":"` + password + `"}`
		recorder := serve(s, request(capture, "/api/v1/account/email", body, accountAPIToken().Claims))
		require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())

		require.True(t, s.jobs.Wait(30*time.Second), "the notice job must finish")
		assert.Equal(t, []string{previousEmail}, capture.recipients(), "the previous address is told, and no other")
	})

	t.Run("an administrator's change notifies neither address", func(t *testing.T) {
		capture := newSMTPCapture(t)

		database := mocks_data.NewDatabase(t)
		database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(&record.User{
			Id:      1,
			Enabled: true,
			Subject: routesTestSubject,
			Email:   previousEmail,
		}, nil)
		database.On("GetUserBySubject", mock.Anything, mock.Anything, routesTestSubject).Return(&record.User{
			Id:      1,
			Subject: routesTestSubject,
			Email:   previousEmail,
		}, nil)
		database.On("GetUserByEmail", mock.Anything, mock.Anything, newEmail).Return((*record.User)(nil), nil)
		database.On("UpdateUser", mock.Anything, mock.Anything, mock.MatchedBy(func(user *record.User) bool {
			return user.Id == 1 && user.Email == newEmail
		})).Return(nil).Once()
		s := newServer(t, database)

		// A client_credentials token with the manage scope: no auth_time, so no session to check,
		// and no current password in the body, which an administrator's change does not take.
		adminClaims := jwt.MapClaims{
			"sub":   "admin-console-client",
			"scope": builtin.AuthServerResourceIdentifier + ":" + builtin.ManagePermissionIdentifier,
		}
		body := `{"email":"` + newEmail + `","emailVerified":true}`
		recorder := serve(s, request(capture, "/api/v1/admin/users/1/email", body, adminClaims))
		require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())

		require.True(t, s.jobs.Wait(30*time.Second), "every job the change started must finish")
		assert.Zero(t, capture.connectionCount(), "no mail of any kind may be attempted")
		assert.Empty(t, capture.recipients(), "neither the previous nor the new address is told")
	})
}

// noticeTestServer runs the real initRoutes on database, with the server's own after-response
// runner, which is what the notice tests wait on before they read their capture.
func noticeTestServer(t *testing.T, database *mocks_data.Database) *Server {
	t.Helper()
	s := &Server{
		router:       chi.NewRouter(),
		database:     database,
		sessionStore: newTestSessionStore(),
		templateFS:   web.TemplateFS(),
		cfg:          &config.Config{},
		jobs:         afterresponse.New(),
	}
	s.initRoutes(appBranches{pages: s.router, protocol: s.router, api: s.router})
	return s
}

// noticeTestRequest is a PUT to target carrying claims as the validated bearer token, with SMTP on
// and pointed at capture.
func noticeTestRequest(capture *smtpCapture, target string, body string, claims jwt.MapClaims) *http.Request {
	settings := routesTestSettings()
	settings.SMTPHost = "127.0.0.1"
	settings.SMTPPort = capture.port
	settings.SMTPEncryption = "none"
	settings.SMTPFromEmail = "noreply@example.com"

	r := httptest.NewRequest(http.MethodPut, target, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	ctx := reqctx.WithBearerToken(r.Context(), oauth.JwtToken{Claims: claims})
	return r.WithContext(reqctx.WithSettings(ctx, settings))
}

// TestInitRoutes_ConcurrentEmailChangesNotifyThePreviousAddressOnce is the notice's bound under
// concurrency, with a completion barrier the integration tier cannot have (#404). That tier runs
// the server in another process, so it counts notices once the first has arrived and cannot see a
// duplicate still in flight. Here the routes, the handler, the after-response runner and the mail
// sender are the production ones, and the count is read after the server's own Jobs.Wait, so
// every notice any of the requests started has been delivered to the capture or never existed.
//
// The database is a fake holding one row, whose TrySetUserEmail is the compare-and-set the engines
// perform, under a mutex; the data tier proves the engines perform it. It also holds every caller
// at the write until all of them have arrived, so every request read the verified address before
// any change landed: the worst case, made certain rather than likely. A handler that acted on its
// read rather than on what the write reported would notify the previous address once per request.
func TestInitRoutes_ConcurrentEmailChangesNotifyThePreviousAddressOnce(t *testing.T) {
	const (
		changes       = 8
		previousEmail = "previous@example.com"
		password      = "the account's real password"
	)
	passwordHash, err := passwordhash.Hash(password)
	require.NoError(t, err)

	var mu sync.Mutex
	row := record.User{Id: 1, Enabled: true, Subject: routesTestSubject, Email: previousEmail,
		EmailVerified: true, PasswordHash: passwordHash}

	arrived := 0
	allArrived := make(chan struct{})

	database := mocks_data.NewDatabase(t)
	database.EXPECT().GetUserBySubject(mock.Anything, mock.Anything, routesTestSubject).
		RunAndReturn(func(context.Context, *sql.Tx, string) (*record.User, error) {
			mu.Lock()
			defer mu.Unlock()
			read := row
			return &read, nil
		}).Maybe()
	database.On("GetUserByEmail", mock.Anything, mock.Anything, mock.Anything).Return((*record.User)(nil), nil).Maybe()
	database.EXPECT().TrySetUserEmail(mock.Anything, mock.Anything, int64(1), mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, _ *sql.Tx, _ int64, fromEmail string, fromVerified bool, toEmail string) (bool, error) {
			mu.Lock()
			arrived++
			if arrived == changes {
				close(allArrived)
			}
			mu.Unlock()
			select {
			case <-allArrived:
			case <-time.After(10 * time.Second):
				return false, errs.New("not every change reached the write")
			}

			mu.Lock()
			defer mu.Unlock()
			if row.Email != fromEmail || row.EmailVerified != fromVerified {
				return false, nil
			}
			row.Email, row.EmailVerified = toEmail, false
			return true, nil
		}).Times(changes)

	capture := newSMTPCapture(t)
	s := noticeTestServer(t, database)

	codes := make([]int, changes)
	var wg sync.WaitGroup
	for i := 0; i < changes; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := fmt.Sprintf(`{"email":"new-%d@example.com","currentPassword":"%s"}`, i, password)
			codes[i] = serve(s, noticeTestRequest(capture, "/api/v1/account/email", body, accountAPIToken().Claims)).Code
		}(i)
	}
	wg.Wait()

	changed, conflicted := 0, 0
	for i, code := range codes {
		switch code {
		case http.StatusOK:
			changed++
		case http.StatusConflict:
			conflicted++
		default:
			t.Errorf("change %d answered %d", i, code)
		}
	}
	assert.Equal(t, 1, changed, "every request read the same row, so exactly one change is made")
	assert.Equal(t, changes-1, conflicted, "every other change answers 409")

	require.True(t, s.jobs.Wait(30*time.Second), "every notice job must finish")
	assert.Equal(t, []string{previousEmail}, capture.recipients(), "the previous address is told once, and no other")
}

// smtpCapture is an SMTP relay on a loopback port that accepts every message and records each
// connection and recipient. A connection is counted when it is accepted, before the greeting the
// client waits for, so a send that has returned has been counted.
type smtpCapture struct {
	port int

	mu          sync.Mutex
	connections int
	rcpts       []string
}

func newSMTPCapture(t *testing.T) *smtpCapture {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	c := &smtpCapture{port: listener.Addr().(*net.TCPAddr).Port}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			c.mu.Lock()
			c.connections++
			c.mu.Unlock()
			go c.serve(conn)
		}
	}()
	return c
}

func (c *smtpCapture) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	r := bufio.NewReader(conn)
	say := func(s string) { _, _ = fmt.Fprint(conn, s+"\r\n") }

	say("220 capture ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		up := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
			say("250 capture")
		case strings.HasPrefix(up, "RCPT TO:"):
			rcpt := strings.Trim(strings.TrimSpace(line[len("RCPT TO:"):]), "<>")
			c.mu.Lock()
			c.rcpts = append(c.rcpts, rcpt)
			c.mu.Unlock()
			say("250 ok")
		case up == "DATA":
			say("354 go ahead")
			for {
				dataLine, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if dataLine == ".\r\n" {
					break
				}
			}
			say("250 ok")
		case up == "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func (c *smtpCapture) connectionCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connections
}

func (c *smtpCapture) recipients() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.rcpts...)
}
