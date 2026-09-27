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
var (
	version  = "dev"
	imageTag = "latest"
)

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
