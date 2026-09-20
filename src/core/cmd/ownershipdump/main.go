// Command ownershipdump regenerates the table in src/core/OWNERSHIP.md, one row per exported
// symbol every core package declares (#385).
//
//	cd src/core && go run ./cmd/ownershipdump
//
// It needs nothing running and reads nothing but the source tree, so unlike schemadump it is not
// tied to the dev container. Run it whenever a core package gains, loses or moves an exported
// symbol: all three module unit tiers compare the committed table against the tree, and the lint
// tier runs this command and fails on a tree it changed.
//
// It writes the four computed justifications from the reference graph and preserves the three a
// human asserts, together with every note. What it will not do is invent a justification: a symbol
// the tree does not justify and nobody has argued for stops this command with a non-zero exit
// naming it, because a tool that filled that cell in would be answering the one question the table
// exists to ask.
//
// The census it writes from is testutil.RenderSymbolOwnership, which is the census the guard
// checks with. There is one implementation of it on purpose, and the cost is that this dev-only
// binary links testing through core/testutil -- acceptable for a tool no Dockerfile builds.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/testutil"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "ownershipdump: %+v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cwd, err := os.Getwd()
	if err != nil {
		return errs.Wrap(err, "getting the working directory")
	}
	root, err := testutil.FindSourceRoot(cwd)
	if err != nil {
		return errs.Wrap(err, "finding the source root")
	}

	doc, unjustified, err := testutil.RenderSymbolOwnership(root)
	if err != nil {
		return err
	}
	if len(unjustified) > 0 {
		// Named in full rather than counted, because the fix is per symbol: move it out of core,
		// or write test-support, contract or moving with the reason.
		for _, symbol := range unjustified {
			fmt.Fprintf(os.Stderr, "no justification for %s\n", symbol)
		}
		return errs.Errorf("%d symbols have no computed justification and no asserted row; move each one out of core, or give it a test-support, contract or moving row with a note", len(unjustified))
	}

	path := filepath.Join(root, "core", "OWNERSHIP.md")
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		return errs.Wrapf(err, "writing %s", path)
	}
	fmt.Printf("wrote %s\n", path)
	return nil
}
