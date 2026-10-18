// Command goiabada-setup writes the configuration a Goiabada deployment starts from: a Docker
// Compose file for local testing or for production behind a reverse proxy, a Kubernetes manifest,
// or an environment file for the native binaries, with the session keys, the data encryption key,
// the admin console's client secret and any password not given generated for it.
//
//	goiabada-setup             ask for every answer
//	goiabada-setup --type ...  take every answer from flags, asking for none
//
// Every secret it generates is drawn from crypto/rand, and the file holding them is written 0600,
// through a temporary file renamed over the destination (#426). Every value the operator answers
// is quoted for the format it lands in, so no answer can change the file's meaning (#430). It may
// not import the auth server (ARCHITECTURE.md rule 3), so the database connection it tests for a
// Kubernetes or native configuration is dialled with copies of the server's connection strings,
// which a shared fixture pins to the originals.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"golang.org/x/term"
)

// Injected at build time via -ldflags by build-binaries.sh, which takes the
// value from the git tag. They are vars rather than consts precisely so the
// linker can set them.
//
// The defaults are what a source build gets. "dev" identifies an unreleased
// binary, and "latest" is the right image tag for someone running the wizard
// from a checkout: it resolves to the current release rather than to whichever
// version happened to be hardcoded when the file was last edited.
//
// The digests are what a release build gets: the release workflow pushes the
// images before it links the wizard, then stamps the manifest digests it read
// from buildx's metadata, so every deployment the wizard writes names the
// image content itself, not only the mutable tag under which it was pushed.
// A source build, or a test, stamps none, and the image reference stays the
// tag alone.
var (
	version            = "dev"
	imageTag           = "latest"
	authserverDigest   = ""
	adminconsoleDigest = ""
)

// imageRef returns the reference a generated deployment points at one of the
// two published images with: its tag, and the digest the release build
// stamped when it knows one, so a re-push under the same tag cannot change
// what a node pulls next. Without a digest, the reference is the tag alone,
// which is what a source build and a test should see.
func imageRef(name string) string {
	ref := "leodip/goiabada:" + name + "-" + imageTag
	if digest := digestFor(name); digest != "" {
		return ref + "@" + digest
	}

	return ref
}

// digestFor returns the manifest digest the release build stamped for one of
// the two published images, or the empty string when it stamped none.
func digestFor(name string) string {
	switch name {
	case "authserver":
		return authserverDigest
	case "adminconsole":
		return adminconsoleDigest
	}

	return ""
}

// main is the wizard's one exit. Everything under it returns an error instead, so a failure deep
// in a prompt or a step is reported, and its exit code chosen, here and nowhere else (#430).
func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	flags, err := parseFlags(args, os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		return 2
	}
	if flags.Version {
		fmt.Printf("goiabada-setup version %s\n", version)
		return 0
	}

	out := &console{w: os.Stdout}
	if !flags.NoColor && term.IsTerminal(int(os.Stdout.Fd())) {
		out.palette = ansiColors
	}
	return exitCode(out, newWizard(flags, newPrompter(os.Stdin, os.Stdout), out).setup())
}

// exitCode reports how the wizard ended: 0 when it finished or the operator ended it, and 1, with
// the error, for anything else.
func exitCode(out *console, err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errAborted):
		out.println()
		out.println("Aborted.")
		return 0
	default:
		out.fail("%v", err)
		return 1
	}
}
