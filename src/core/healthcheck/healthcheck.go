// Package healthcheck is the `healthcheck` command both servers' binaries run: one GET of the
// server's own /health, the answer an image's, Compose's or an orchestrator's health check reads
// from the exit code, since the images hold no other program to ask with (#808).
//
// It reads only the variables that pick the listener, the HTTP and HTTPS hosts and ports and
// whether the certificate and key files are named, by the rules each server's configuration reads
// them with, and nothing else: no TZ, no flags, no log handler, no file. A setting it does not read
// cannot fail it, so a check runs whatever else the deployment has wrong, and says only whether the
// server answers.
package healthcheck

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/hostport"
)

// The command's exit codes: healthy, unhealthy, and a listener setting that does not parse or an
// argument given, the code every malformed setting and flag of the servers exits with. Docker
// counts any code but 0 as unhealthy.
const (
	exitHealthy   = 0
	exitUnhealthy = 1
	exitUsage     = 2
)

// timeout bounds the one request, connection and answer together.
const timeout = 3 * time.Second

// Listeners names the variables one server's two listeners are configured by, and the defaults its
// configuration gives them when a variable is unset or empty.
type Listeners struct {
	// Command is the binary's name, for the refusal of an argument.
	Command string

	HTTPHost, HTTPPort   string
	HTTPSHost, HTTPSPort string
	CertFile, KeyFile    string

	DefaultHost      string
	DefaultHTTPPort  int
	DefaultHTTPSPort int
}

// ArgumentsRefused is the refusal of any argument given with the command, before it or after it:
// the listener is read from the environment, because an automatic check is a process of its own and
// inherits none of the server's flags.
func ArgumentsRefused(command string) error {
	return errs.Errorf("healthcheck takes no arguments: it reads the listener from the environment, "+
		"so run %s healthcheck alone", command)
}

// Run is the command, given what followed its word on the command line, and answers the code the
// process exits with. It writes nothing when healthy, and otherwise one line on stderr.
func Run(listeners Listeners, args []string, stderr io.Writer) int {
	if len(args) > 0 {
		_, _ = fmt.Fprintln(stderr, ArgumentsRefused(listeners.Command))
		return exitUsage
	}
	target, enabled, err := listeners.healthURL()
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return exitUsage
	}
	if !enabled {
		_, _ = fmt.Fprintln(stderr, "neither the http nor the https listener is enabled, so there is no /health to check")
		return exitUnhealthy
	}
	if err := check(target); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return exitUnhealthy
	}
	return exitHealthy
}

// healthURL is the /health of the listener the server's own rule enables: the HTTP one when it has
// a host and a port above 0, and otherwise the HTTPS one when it has both and its certificate and
// key files are named. enabled is false when neither is. Every port is read, either listener's, so
// a malformed one is refused whichever is asked, as at the server's start.
func (l Listeners) healthURL() (target string, enabled bool, err error) {
	var malformed []string
	httpsHost := setting(l.HTTPSHost, l.DefaultHost)
	httpsPort := port(l.HTTPSPort, l.DefaultHTTPSPort, &malformed)
	httpHost := setting(l.HTTPHost, l.DefaultHost)
	httpPort := port(l.HTTPPort, l.DefaultHTTPPort, &malformed)
	if len(malformed) > 0 {
		return "", false, errs.Errorf("malformed configuration: %s", strings.Join(malformed, "; "))
	}

	switch {
	case httpHost != "" && httpPort > 0:
		return "http://" + hostport.Join(callable(httpHost), httpPort) + "/health", true, nil
	case httpsHost != "" && httpsPort > 0 && setting(l.CertFile, "") != "" && setting(l.KeyFile, "") != "":
		return "https://" + hostport.Join(callable(httpsHost), httpsPort) + "/health", true, nil
	}
	return "", false, nil
}

// setting is a variable as the servers' configurations read one: trimmed, and the default only when
// it is unset, so a variable set empty is empty.
func setting(name, defaultValue string) string {
	if value, ok := os.LookupEnv(name); ok {
		return strings.TrimSpace(value)
	}
	return defaultValue
}

// port is a port variable as the servers' configurations read one: the default when it is unset or
// empty, and recorded in malformed when it is not an integer.
func port(name string, defaultValue int, malformed *[]string) int {
	value := setting(name, "")
	if value == "" {
		return defaultValue
	}
	number, err := strconv.Atoi(value)
	if err != nil {
		*malformed = append(*malformed, name+" is "+strconv.Quote(value)+", not an integer")
		return defaultValue
	}
	return number
}

// callable is the host to call a listener on: a wildcard address, which a server listens on but
// nothing can call, becomes its family's loopback, and any other host is called as configured.
func callable(host string) string {
	address, err := netip.ParseAddr(hostport.Unbracket(host))
	if err != nil || !address.IsUnspecified() {
		return host
	}
	if address.Is4() {
		return "127.0.0.1"
	}
	return "::1"
}

// check makes the one GET of target and answers why it is unhealthy, or nil for a 200.
//
// It follows no redirect and goes through no proxy: it is the process asking its own listener
// whether it answers. Over HTTPS the certificate is not verified, for this request alone: the
// certificate names the public host and not the address called, and verifying it would need the
// file read too. Nothing is sent and no body is read, so nothing rests on the peer's identity, which
// is how the kubelet's HTTPS probe asks as well.
func check(target string) error {
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:             nil,
			DisableKeepAlives: true,
			//nolint:gosec // G402: the process asking its own listener, sending nothing and reading no body (#808 decision 2)
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
	if err != nil {
		return errs.Errorf("GET %s failed: %w", target, err)
	}
	response, err := client.Do(request)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return errs.Errorf("GET %s had no answer within %s", target, timeout)
		}
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return errs.Errorf("GET %s failed: %w", target, err)
	}
	_ = response.Body.Close()

	if response.StatusCode == http.StatusOK {
		return nil
	}
	if location := response.Header.Get("Location"); location != "" {
		return errs.Errorf("GET %s answered %s, a redirect to %q", target, response.Status, location)
	}
	return errs.Errorf("GET %s answered %s", target, response.Status)
}
