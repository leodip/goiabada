// Package buildinfo holds the build stamp both servers report: the version, the build date and the
// git commit. The release builds set all three with -ldflags -X, and a binary built any other way
// reports "development" (#442).
//
// It is apart from core/builtin because these are not identifiers the two processes agree on but
// values the linker writes, and TestReleaseBuilds_TheRealStampsNameVariables holds every -X target in
// the release builds to naming one of them: the linker ignores an -X that names nothing.
package buildinfo

var Version = "development"
var BuildDate = "development"
var GitCommit = "development"
