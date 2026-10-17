// Package refgraph reads the source tree as a reference graph: which package imports which,
// which files a production build excludes, the markdown tables ARCHITECTURE.md and OWNERSHIP.md
// hold as data, and the census of every exported core symbol with what names it. The source
// root itself is core/sourceroot's, the one declaration the tree-wide guards, cmd/ownershipdump
// and the auth server's schemadump share (#480).
//
// It is the half of the tree-wide guards that is not a test. core/guard keeps every Assert* and
// reporting half and reads the tree through this package, and cmd/ownershipdump writes
// OWNERSHIP.md's table from the same census the guard checks it with, so the tool and the guard
// cannot read the tree differently. Living here rather than in core/guard is what keeps
// ownershipdump from linking testing and testify, and it lives under core/internal because nothing
// outside core has a reason to name it (#431).
package refgraph
