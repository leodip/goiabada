package main

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

// nativeDirectConfig is a native install with no reverse proxy on the same machine, at the two URLs.
func nativeDirectConfig(authServerURL, adminConsoleURL string) *Config {
	config := testConfig()
	config.Deployment = deployments[deploymentNative]
	config.LocalProxy = false
	config.AuthServerURL, config.AdminConsoleURL = authServerURL, adminConsoleURL
	return config
}

// listenerComment is the block of comment lines directly above the server's HTTP listen host, as
// the env file writes them.
func listenerComment(t *testing.T, content, server string) string {
	t.Helper()
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if !strings.HasPrefix(line, "GOIABADA_"+server+"_LISTEN_HOST_HTTP=") {
			continue
		}
		start := i
		for start > 0 && strings.HasPrefix(lines[start-1], "#") {
			start--
		}
		return strings.Join(lines[start:i], "\n")
	}
	t.Fatalf("the env file sets no GOIABADA_%s_LISTEN_HOST_HTTP:\n%s", server, content)
	return ""
}

// The comment above a native server's HTTP listener, with no proxy in front: with an https URL the
// listener only redirects, before the certificate and after it, so the server serves no page until
// HTTPS is set, and the advice to set the listen host empty once it is stays, with keeping the
// listener for a port-80 forward as the alternative; with an http URL the comment is today's (#715
// decisions 7 and 12). Each server's comment follows its own URL.
func TestEnvFile_NativeHTTPListenerCommentFollowsTheServersURL(t *testing.T) {
	redirecting := map[string]string{
		"AUTHSERVER": `# No reverse proxy fronts this server: it listens on every interface and trusts no
# forwarded header, so each client is the address it connects from. Its URL is https, so
# its plain HTTP listener only redirects there, and it serves no page until you set
# GOIABADA_AUTHSERVER_CERTFILE and GOIABADA_AUTHSERVER_KEYFILE, which turn on HTTPS at
# 0.0.0.0:9443 (GOIABADA_AUTHSERVER_LISTEN_HOST_HTTPS and _LISTEN_PORT_HTTPS change it).
# Then set the HTTP listen host below empty, or keep this listener to redirect visitors
# to HTTPS when you forward port 80 to it.`,
		"ADMINCONSOLE": `# No reverse proxy fronts this server: it listens on every interface and trusts no
# forwarded header, so each client is the address it connects from. Its URL is https, so
# its plain HTTP listener only redirects there, and it serves no page until you set
# GOIABADA_ADMINCONSOLE_CERTFILE and GOIABADA_ADMINCONSOLE_KEYFILE, which turn on HTTPS at
# 0.0.0.0:9444 (GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTPS and _LISTEN_PORT_HTTPS change it).
# Then set the HTTP listen host below empty, or keep this listener to redirect visitors
# to HTTPS when you forward port 80 to it.`,
	}
	serving := map[string]string{
		"AUTHSERVER": `# No reverse proxy fronts this server: it listens on every interface and trusts no
# forwarded header, so each client is the address it connects from. It serves plain HTTP
# until you set GOIABADA_AUTHSERVER_CERTFILE and GOIABADA_AUTHSERVER_KEYFILE, which turn
# on HTTPS at 0.0.0.0:9443 (GOIABADA_AUTHSERVER_LISTEN_HOST_HTTPS and _LISTEN_PORT_HTTPS
# change it); then set the HTTP listen host below empty to stop serving plain HTTP.`,
		"ADMINCONSOLE": `# No reverse proxy fronts this server: it listens on every interface and trusts no
# forwarded header, so each client is the address it connects from. It serves plain HTTP
# until you set GOIABADA_ADMINCONSOLE_CERTFILE and GOIABADA_ADMINCONSOLE_KEYFILE, which turn
# on HTTPS at 0.0.0.0:9444 (GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTPS and _LISTEN_PORT_HTTPS
# change it); then set the HTTP listen host below empty to stop serving plain HTTP.`,
	}
	tests := []struct {
		name                             string
		authServerURL, adminURL          string
		wantAuthServer, wantAdminConsole string
	}{
		{"https URLs", "https://auth.example.com", "https://admin.example.com", redirecting["AUTHSERVER"], redirecting["ADMINCONSOLE"]},
		{"http URLs", "http://localhost:9090", "http://localhost:9091", serving["AUTHSERVER"], serving["ADMINCONSOLE"]},
		{"an https auth server and an http admin console", "https://auth.example.com", "http://localhost:9091", redirecting["AUTHSERVER"], serving["ADMINCONSOLE"]},
		{"an http auth server and an https admin console", "http://auth.example.com", "https://admin.example.com", serving["AUTHSERVER"], redirecting["ADMINCONSOLE"]},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			content := descriptionOf(nativeDirectConfig(test.authServerURL, test.adminURL))
			if got := listenerComment(t, content, "AUTHSERVER"); got != test.wantAuthServer {
				t.Errorf("the auth server's listener comment is\n%s\nwant\n%s", got, test.wantAuthServer)
			}
			if got := listenerComment(t, content, "ADMINCONSOLE"); got != test.wantAdminConsole {
				t.Errorf("the admin console's listener comment is\n%s\nwant\n%s", got, test.wantAdminConsole)
			}
			for _, server := range []string{"AUTHSERVER", "ADMINCONSOLE"} {
				if !strings.Contains(content, "GOIABADA_"+server+"_LISTEN_HOST_HTTP=\"0.0.0.0\"\n") {
					t.Errorf("the env file does not keep GOIABADA_%s_LISTEN_HOST_HTTP at 0.0.0.0", server)
				}
			}
		})
	}
}

// Behind a reverse proxy on the same machine the listener serves whatever the URLs, so its comment
// says nothing of a redirect (#715: the native-with-proxy output is unchanged).
func TestEnvFile_NativeHTTPListenerCommentBehindALocalProxySaysNoRedirect(t *testing.T) {
	config := nativeDirectConfig("https://auth.example.com", "https://admin.example.com")
	config.LocalProxy = true
	content := descriptionOf(config)
	for _, server := range []string{"AUTHSERVER", "ADMINCONSOLE"} {
		if comment := listenerComment(t, content, server); strings.Contains(comment, "redirect") {
			t.Errorf("behind a local proxy the %s listener comment speaks of a redirect:\n%s", server, comment)
		}
	}
}

// nativeNotes is the native instructions printed for the config, with the env file goiabada.env.
func nativeNotes(config *Config) string {
	var buf bytes.Buffer
	printNativeInstructions(&console{w: &buf}, config, outputPaths{description: "goiabada.env"})
	return buf.String()
}

// listenerNote is the notes' bullet on the listeners, its lines unwrapped into one paragraph.
func listenerNote(t *testing.T, notes string) string {
	t.Helper()
	lines := strings.Split(notes, "\n")
	for i, line := range lines {
		if !strings.HasPrefix(line, "  • Both servers listen on every interface") {
			continue
		}
		var words []string
		for _, l := range lines[i:] {
			if strings.TrimSpace(l) == "" {
				break
			}
			words = append(words, strings.Fields(strings.TrimPrefix(l, "  •"))...)
		}
		return strings.Join(words, " ")
	}
	t.Fatalf("the notes have no bullet on the listeners:\n%s", notes)
	return ""
}

// The printed notes of a native install with no proxy say what each listener does: with https URLs
// the plain HTTP listener only redirects, so the server serves no page until HTTPS is set, and then
// its listen host goes empty or it stays to redirect a port-80 forward; with http URLs the bullet is
// today's, line for line (#715 decisions 7 and 12).
func TestNativeInstructions_ListenerNoteFollowsTheURLs(t *testing.T) {
	tests := []struct {
		name                    string
		authServerURL, adminURL string
		want                    string
	}{
		{"https URLs", "https://auth.example.com", "https://admin.example.com",
			"Both servers listen on every interface, and with https URLs their plain HTTP listeners " +
				"only redirect to HTTPS: they serve no page until you set their CERTFILE and KEYFILE in " +
				"goiabada.env, as its comments say. Then set their HTTP listen hosts empty, or keep a " +
				"listener to redirect visitors to HTTPS when you forward port 80 to it. The admin console " +
				"reaches the auth server at its public URL, so it waits to listen until the auth server " +
				"serves HTTPS there."},
		{"an https auth server and an http admin console", "https://auth.example.com", "http://localhost:9091",
			"Both servers listen on every interface. The auth server's URL is https, so its plain HTTP " +
				"listener only redirects to HTTPS: it serves no page until you set its CERTFILE and KEYFILE " +
				"in goiabada.env, as its comments say. Then set its HTTP listen host empty, or keep the " +
				"listener to redirect visitors to HTTPS when you forward port 80 to it. The admin " +
				"console's URL is http, so it serves plain HTTP until you set its own CERTFILE and KEYFILE. " +
				"The admin console reaches the auth server at its public URL, so it waits to listen until " +
				"the auth server serves HTTPS there."},
		{"an http auth server and an https admin console", "http://auth.example.com", "https://admin.example.com",
			"Both servers listen on every interface. The admin console's URL is https, so its plain HTTP " +
				"listener only redirects to HTTPS: it serves no page until you set its CERTFILE and KEYFILE " +
				"in goiabada.env, as its comments say. Then set its HTTP listen host empty, or keep the " +
				"listener to redirect visitors to HTTPS when you forward port 80 to it. The auth " +
				"server's URL is http, so it serves plain HTTP until you set its own CERTFILE and KEYFILE. " +
				"The admin console reaches the auth server at its public URL, so it waits to listen until " +
				"the auth server answers there."},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			notes := nativeNotes(nativeDirectConfig(test.authServerURL, test.adminURL))
			if got := listenerNote(t, notes); got != test.want {
				t.Errorf("the listener note is\n%s\nwant\n%s", got, test.want)
			}
			for _, line := range strings.Split(notes, "\n") {
				if utf8.RuneCountInString(line) > 80 {
					t.Errorf("the notes line is %d columns wide, over 80: %q", utf8.RuneCountInString(line), line)
				}
			}
		})
	}

	t.Run("http URLs", func(t *testing.T) {
		notes := nativeNotes(nativeDirectConfig("http://localhost:9090", "http://localhost:9091"))
		today := "  • Both servers listen on every interface and serve plain HTTP until you set\n" +
			"    their CERTFILE and KEYFILE in goiabada.env, as its comments say. The admin console\n" +
			"    reaches the auth server at its public URL, so it waits to listen until the\n" +
			"    auth server serves HTTPS there.\n\n"
		if !strings.Contains(notes, today) {
			t.Errorf("the notes for http URLs do not keep today's listener bullet:\n%s", notes)
		}
		if strings.Contains(notes, "redirect") {
			t.Errorf("the notes for http URLs speak of a redirect:\n%s", notes)
		}
	})

	t.Run("behind a local proxy", func(t *testing.T) {
		config := nativeDirectConfig("https://auth.example.com", "https://admin.example.com")
		config.LocalProxy = true
		notes := nativeNotes(config)
		if !strings.Contains(notes, "  • Both servers listen on 127.0.0.1 alone.") {
			t.Errorf("the notes behind a local proxy lost the loopback bullet:\n%s", notes)
		}
		if strings.Contains(notes, "redirect") {
			t.Errorf("the notes behind a local proxy speak of a redirect:\n%s", notes)
		}
	})
}
