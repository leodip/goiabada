package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// runPrinted runs a command the wizard printed through a POSIX shell in dir, after prelude, and
// answers each line it wrote.
func runPrinted(t *testing.T, dir, prelude, command string) []string {
	t.Helper()
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh to run the printed command with")
	}
	cmd := exec.Command(shell, "-c", prelude+"\n"+command)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", command, err, output)
	}
	return strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")
}

// Every command the completion message prints names the files the wizard wrote, whatever name
// --output gave them: a space, a quote or a glob character in the name is one argument of the
// command the operator pastes, and not two, a syntax error, or the files a pattern matches. Each
// command is run through sh, its tool replaced by a function printing the arguments it receives,
// in a directory holding a decoy file the glob would match.
func TestWizard_PrintedCommandsNameTheWrittenFiles(t *testing.T) {
	for _, name := range []string{"identity deploy", "o'brien", "id[x]*"} {
		t.Run("kubernetes "+name, func(t *testing.T) {
			dir := t.TempDir()
			writeDecoy(t, dir, "idxa.yaml")
			w, _, out, _ := testWizard(t, flagsFor(deploymentKubernetes, filepath.Join(dir, name+".yaml")), nil)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			got := runPrinted(t, dir, `kubectl() { printf '%s\n' "$@"; }`, completionLine(t, out.String(), "kubectl apply -f '"))
			want := []string{"apply", "-f", name + "-secrets.yaml", "-f", name + ".yaml"}
			if !slices.Equal(got, want) {
				t.Errorf("kubectl receives %q, want %q", got, want)
			}
		})
		t.Run("production "+name, func(t *testing.T) {
			dir := t.TempDir()
			writeDecoy(t, dir, "idxa.yml")
			w, _, out, _ := testWizard(t, flagsFor(deploymentProduction, filepath.Join(dir, name+".yml")), nil)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			got := runPrinted(t, dir, `docker() { printf '%s\n' "$@"; }`, completionLine(t, out.String(), "docker compose"))
			want := []string{"compose", "-f", name + ".yml", "-f", name + ".override.yml", "up", "-d"}
			if !slices.Equal(got, want) {
				t.Errorf("docker receives %q, want %q", got, want)
			}
		})
		t.Run("native "+name, func(t *testing.T) {
			dir := t.TempDir()
			writeDecoy(t, dir, "idxa.env")
			w, _, out, _ := testWizard(t, flagsFor(deploymentNative, filepath.Join(dir, name+".env")), nil)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			// A stand-in binary prints the variable the env file set, which it sees only when the
			// command loaded that file.
			binary := filepath.Join(dir, "goiabada-authserver")
			if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf '%s\\n' \"$GOIABADA_ADMIN_EMAIL\"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			got := runPrinted(t, dir, "", completionLine(t, out.String(), "./goiabada-authserver"))
			if want := []string{w.config.AdminEmail}; !slices.Equal(got, want) {
				t.Errorf("the auth server starts with GOIABADA_ADMIN_EMAIL %q, want %q", got, want)
			}
		})
	}
}

func writeDecoy(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("decoy\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

// Each generated file's header names the files beside it by the names they were written under, and
// gives the command that starts or applies them as the completion message does: a header naming
// the default files sent an operator who chose another name to files that were never written, and
// told them docker compose would merge an override it does not look for (#396 decision 14). The
// default names stay what the goldens hold.
func TestGeneratedHeaders_NameTheFilesAsWritten(t *testing.T) {
	cases := []struct {
		name     string
		kind     deploymentType
		output   string
		header   []string
		override []string
		defaults []string
	}{
		{
			name: "kubernetes renamed", kind: deploymentKubernetes, output: "identity deploy.yaml",
			header:   []string{"#   kubectl apply -f 'identity deploy-secrets.yaml' -f 'identity deploy.yaml'\n", "# This file holds no secret: every one is in identity deploy-secrets.yaml.\n"},
			override: []string{"# The Secrets identity deploy.yaml reads.", "#   kubectl apply -f 'identity deploy-secrets.yaml' -f 'identity deploy.yaml'\n"},
			defaults: []string{"goiabada-k8s.yaml", "goiabada-secrets.yaml"},
		},
		{
			name: "compose renamed", kind: deploymentProduction, output: "identity.yml",
			header:   []string{"# Run: docker compose -f identity.yml -f identity.override.yml up -d\n", "# identity.override.yml, beside it.\n"},
			override: []string{"# Every secret of identity.yml,", "# this file into identity.yml when both are named, that one first,", "#   docker compose -f identity.yml -f identity.override.yml up -d\n"},
			defaults: []string{"docker-compose", "without being asked", "docker compose up -d"},
		},
		{
			name: "compose under another name it looks for", kind: deploymentProduction, output: "compose.yaml",
			header:   []string{"# Run: docker compose up -d\n", "# compose.override.yaml, beside it.\n"},
			override: []string{"# Every secret of compose.yaml,", "# this file into compose.yaml without being asked,", "so docker compose up -d starts both.\n"},
			defaults: []string{"docker-compose"},
		},
		{
			name: "native renamed", kind: deploymentNative, output: "prod's.env",
			header:   []string{"#   set -a && . './prod'\\''s.env' && set +a && ./goiabada-authserver\n", "EnvironmentFile=/path/to/prod's.env\n"},
			defaults: []string{"goiabada.env"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := testConfig()
			config.Deployment = deployments[tc.kind]
			description, secrets := writtenConfiguration(config, resolveOutputPaths(config.Deployment, filepath.Join(t.TempDir(), tc.output)))
			files := map[string][]string{description.content: tc.header}
			if secrets != description {
				files[secrets.content] = tc.override
			}
			for content, wanted := range files {
				for _, want := range wanted {
					if !strings.Contains(content, want) {
						t.Errorf("the header lacks %q:\n%s", want, header(content))
					}
				}
				for _, stale := range tc.defaults {
					if strings.Contains(header(content), stale) {
						t.Errorf("the header still says %q:\n%s", stale, header(content))
					}
				}
			}
		})
	}
}

// header is a generated file's opening comment, up to its first blank line.
func header(content string) string {
	head, _, _ := strings.Cut(content, "\n\n")
	return head
}

// An --output naming a file whose name holds a line break or another control character is refused
// in both modes before anything is written: the name goes into the header's comment, where a line
// break would end the comment and write the rest of the name as configuration.
func TestWizard_RefusesAnOutputNoHeaderCanName(t *testing.T) {
	for _, name := range []string{"a\nservices: {}\n.yml", "a\r.yml", "a\u2028.yml", "a\x1b.yml"} {
		for _, interactive := range []bool{false, true} {
			t.Run(strings.ToValidUTF8(name, "?")+map[bool]string{false: " flags", true: " interactive"}[interactive], func(t *testing.T) {
				dir := t.TempDir()
				flags := flagsFor(deploymentProduction, filepath.Join(dir, name))
				if interactive {
					flags = &CLIFlags{Output: flags.Output}
				}
				w, _, out, _ := testWizard(t, flags, nil)
				err := w.setup()
				want := "--output cannot be written to the configuration: it contains a control character"
				if err == nil || err.Error() != want {
					t.Fatalf("setup: %v, want %q\n%s", err, want, out)
				}
				assertNothingWritten(t, dir)
			})
		}
	}
}

// The env file's header names it for systemd's EnvironmentFile=, which expands `%` specifiers and
// then reads the path as a glob pattern, so the shell's quoting does not carry over: `id[x]*.env`
// loaded an `idxa.env` beside it, and `identity%Z.env` was ignored. Each name is read back through
// an emulation of those two expansions and must select the file written and not the decoy beside
// it. The escapes were checked against systemd 259's unit loader for every name here.
func TestEnvFileHeader_SystemdNamesTheFileWritten(t *testing.T) {
	cases := []struct{ output, decoy string }{
		{output: "id[x]*.env", decoy: "idxa.env"},
		{output: "q?.env", decoy: "qa.env"},
		{output: `back\slash.env`, decoy: "backslash.env"},
		{output: "identity%Z.env"},
		{output: "100%%.env", decoy: "100%.env"},
		{output: "prod's x.env"},
		{output: "goiabada.env"},
	}
	for _, tc := range cases {
		t.Run(tc.output, func(t *testing.T) {
			config := testConfig()
			config.Deployment = deployments[deploymentNative]
			description, _ := writtenConfiguration(config, resolveOutputPaths(config.Deployment, filepath.Join(t.TempDir(), tc.output)))
			_, setting, found := strings.Cut(header(description.content), "EnvironmentFile=/path/to/")
			if !found {
				t.Fatalf("the header names no EnvironmentFile=:\n%s", header(description.content))
			}
			setting, _, _ = strings.Cut(setting, "\n")
			pattern, err := systemdSpecifiers(setting)
			if err != nil {
				t.Fatalf("systemd ignores EnvironmentFile=/path/to/%s: %v", setting, err)
			}
			if matched, err := filepath.Match(pattern, tc.output); err != nil || !matched {
				t.Errorf("EnvironmentFile=/path/to/%s does not load %q (%v)", setting, tc.output, err)
			}
			if tc.decoy == "" {
				return
			}
			if matched, _ := filepath.Match(pattern, tc.decoy); matched {
				t.Errorf("EnvironmentFile=/path/to/%s loads %q too", setting, tc.decoy)
			}
		})
	}
}

// A name ending in a space has no spelling in a unit file, which strips it, so the header says to
// rename the file rather than name another one.
func TestEnvFileHeader_SystemdCannotNameATrailingSpace(t *testing.T) {
	config := testConfig()
	config.Deployment = deployments[deploymentNative]
	description, _ := writtenConfiguration(config, resolveOutputPaths(config.Deployment, filepath.Join(t.TempDir(), "goiabada.env ")))
	head := header(description.content)
	if strings.Contains(head, "EnvironmentFile=/") {
		t.Errorf("the header names a path systemd would strip:\n%s", head)
	}
	if !strings.Contains(head, "a unit file cannot name one ending in a space") {
		t.Errorf("the header does not say why it names no path:\n%s", head)
	}
}

// systemdSpecifiers is an emulation, not systemd: it expands a unit setting's specifiers as
// systemd.unit(5) describes for a setting holding none but `%%`, which is a literal `%`, and
// refuses any other, which in a generated header names nothing the operator chose.
func systemdSpecifiers(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b.WriteByte(s[i])
			continue
		}
		if i+1 == len(s) || s[i+1] != '%' {
			return "", fmt.Errorf("an unresolved specifier at %q", s[i:])
		}
		b.WriteByte('%')
		i++
	}
	return b.String(), nil
}
