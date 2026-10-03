package server

import (
	"bufio"
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
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/web"
	coreconstants "github.com/leodip/goiabada/core/constants"
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

	newServer := func(t *testing.T, database *mocks_data.Database) *Server {
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

	request := func(capture *smtpCapture, target string, body string, claims jwt.MapClaims) *http.Request {
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

	t.Run("a self-service change notifies the previous address", func(t *testing.T) {
		capture := newSMTPCapture(t)

		database := mocks_data.NewDatabase(t)
		database.On("GetUserBySubject", mock.Anything, mock.Anything, routesTestSubject).Return(&models.User{
			Id:           1,
			Enabled:      true,
			Subject:      routesTestSubject,
			Email:        previousEmail,
			PasswordHash: passwordHash,
		}, nil)
		database.On("GetUserByEmail", mock.Anything, mock.Anything, newEmail).Return((*models.User)(nil), nil)
		database.On("SetUserEmail", mock.Anything, mock.Anything, int64(1), newEmail).Return(nil).Once()
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
		database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(&models.User{
			Id:      1,
			Enabled: true,
			Subject: routesTestSubject,
			Email:   previousEmail,
		}, nil)
		database.On("GetUserBySubject", mock.Anything, mock.Anything, routesTestSubject).Return(&models.User{
			Id:      1,
			Subject: routesTestSubject,
			Email:   previousEmail,
		}, nil)
		database.On("GetUserByEmail", mock.Anything, mock.Anything, newEmail).Return((*models.User)(nil), nil)
		database.On("UpdateUser", mock.Anything, mock.Anything, mock.MatchedBy(func(user *models.User) bool {
			return user.Id == 1 && user.Email == newEmail
		})).Return(nil).Once()
		s := newServer(t, database)

		// A client_credentials token with the manage scope: no auth_time, so no session to check,
		// and no current password in the body, which an administrator's change does not take.
		adminClaims := jwt.MapClaims{
			"sub":   "admin-console-client",
			"scope": coreconstants.AuthServerResourceIdentifier + ":" + coreconstants.ManagePermissionIdentifier,
		}
		body := `{"email":"` + newEmail + `","emailVerified":true}`
		recorder := serve(s, request(capture, "/api/v1/admin/users/1/email", body, adminClaims))
		require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())

		require.True(t, s.jobs.Wait(30*time.Second), "every job the change started must finish")
		assert.Zero(t, capture.connectionCount(), "no mail of any kind may be attempted")
		assert.Empty(t, capture.recipients(), "neither the previous nor the new address is told")
	})
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
