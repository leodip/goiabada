package main

import (
	"context"
	"fmt"
	"io"

	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/adminconsole/internal/publicsettings"
	"github.com/leodip/goiabada/core/errs"
)

// checkAuthServerRefused is the refusal of any argument given with check-authserver, before it or
// after it: like healthcheck, it is a process of its own, and reads what it needs from the
// environment the console runs with (#808 decisions 3 and 6).
func checkAuthServerRefused() error {
	return errs.New("check-authserver takes no arguments: it reads the auth server's URLs and the internal " +
		"CA file from the environment, so run goiabada-adminconsole check-authserver alone")
}

// checkAuthServer is the check-authserver command, given what followed its word on the command
// line, and answers the code the process exits with. It makes the console's own settings call to
// the auth server once, through the public settings client and not its cache, so the call keeps
// that client's 10-second bound, its bounded read and decoding, its refusal of redirects and its
// certificate verification against the system roots and the internal CA file. Settings fetched
// and decoded print one line on stdout naming the URL and exit 0; anything else prints the
// client's error, the one the console logs, on stderr and exits 1. An argument, or an internal CA
// file it cannot use, is exit 2, as a malformed setting is at the console's start (#808
// decision 6).
func checkAuthServer(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		_, _ = fmt.Fprintln(stderr, checkAuthServerRefused())
		return 2
	}
	authServer, internalRoots, err := config.LoadAuthServerCheck()
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}

	// No metrics recorder: the process serves no registry for one to be read from.
	client := publicsettings.NewClient(authServer.GetEffectiveBaseURL(), internalRoots, nil)
	if _, err := client.GetPublicSettings(context.Background()); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "GET %s answered with the auth server's public settings\n", client.URL())
	return 0
}
