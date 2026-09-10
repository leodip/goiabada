package commondb

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/errs"
)

// driverUniqueError stands in for whatever the engine's driver returned. The real types are
// checked at their own seam, in each engine package's TestIsUniqueViolation; what belongs here is
// the translation itself: given a classifier that says yes, what does the rest of the tree see?
type driverUniqueError struct{ msg string }

func (e *driverUniqueError) Error() string { return e.msg }

// classifyingDB is a CommonDatabase whose classifier answers for driverUniqueError and nothing
// else, which is the shape every dialect wires in its constructor.
func classifyingDB() *CommonDatabase {
	d := NewCommonDatabase(nil, sqlbuilder.SQLite, false)
	d.IsUniqueViolation = func(err error) bool {
		var target *driverUniqueError
		return errors.As(err, &target)
	}
	return d
}

// TestWrapSQLError_TagsAClassifiedViolation is the translation WrapSQLError exists for: a driver
// failure the dialect recognised leaves the data layer carrying ErrUniqueViolation, so every
// caller above it asks errors.Is and never a driver number or a driver sentence (#279).
func TestWrapSQLError_TagsAClassifiedViolation(t *testing.T) {
	driverErr := &driverUniqueError{msg: "UNIQUE constraint failed: users.email"}

	err := classifyingDB().WrapSQLError(driverErr, "unable to execute SQL")

	if !errors.Is(err, ErrUniqueViolation) {
		t.Errorf("errors.Is(err, ErrUniqueViolation) = false, want true; err = %v", err)
	}

	// The driver's own error stays in the tree. A caller that needs to know WHICH key was
	// violated has nowhere else to look, since the sentinel deliberately does not say.
	var reached *driverUniqueError
	if !errors.As(err, &reached) || reached != driverErr {
		t.Errorf("errors.As did not reach the driver error; err = %v", err)
	}

	// The prefix is the only change to what this layer has always printed.
	want := "unable to execute SQL: unique constraint violation: UNIQUE constraint failed: users.email"
	if err.Error() != want {
		t.Errorf("err.Error() = %q, want %q", err.Error(), want)
	}
}

// TestWrapSQLError_LeavesAnUnclassifiedErrorExactlyAsItWas is the other half, and it is what stops
// the tagging from becoming a change to every message the data layer emits. A failure the dialect
// did not recognise reads exactly as errs.Wrap has always made it read, and is not the sentinel.
func TestWrapSQLError_LeavesAnUnclassifiedErrorExactlyAsItWas(t *testing.T) {
	driverErr := errors.New("syntax error at or near \"slect\"")

	err := classifyingDB().WrapSQLError(driverErr, "unable to execute SQL")

	if errors.Is(err, ErrUniqueViolation) {
		t.Errorf("an unclassified failure must not carry the sentinel; err = %v", err)
	}
	if want := errs.Wrap(driverErr, "unable to execute SQL").Error(); err.Error() != want {
		t.Errorf("err.Error() = %q, want %q", err.Error(), want)
	}
}

// TestWrapSQLError_WithNoClassifierTagsNothing pins the default a handle built directly on
// CommonDatabase gets. Nothing is a unique violation until a dialect says what one looks like, so
// a fifth engine added later without wiring IsUniqueViolation degrades to today's behaviour rather
// than tagging by accident.
func TestWrapSQLError_WithNoClassifierTagsNothing(t *testing.T) {
	d := NewCommonDatabase(nil, sqlbuilder.SQLite, false)

	err := d.WrapSQLError(&driverUniqueError{msg: "UNIQUE constraint failed: users.email"},
		"unable to execute SQL")

	if errors.Is(err, ErrUniqueViolation) {
		t.Errorf("with no classifier wired, nothing may be tagged; err = %v", err)
	}
}

// TestWrapSQLError_NilInNilOut matches errs.Wrap, which every call site here relies on: the two
// arms of ExecSql and QuerySql call this only inside `if err != nil`, but a caller that does not
// must not receive a non-nil error describing a success.
func TestWrapSQLError_NilInNilOut(t *testing.T) {
	if err := classifyingDB().WrapSQLError(nil, "unable to execute SQL"); err != nil {
		t.Errorf("WrapSQLError(nil, ...) = %v, want nil", err)
	}
}

// TestWrapSQLError_TaggingCostsNoSecondStack is decision 2's rule holding across the two-%w shape.
// The tagged branch builds the error out of two constructors rather than one, and if each captured
// frames a duplicate-key failure would print two stacks in the log where every other failure prints
// one -- which is the whole defect #279 exists to remove.
func TestWrapSQLError_TaggingCostsNoSecondStack(t *testing.T) {
	tagged := classifyingDB().WrapSQLError(&driverUniqueError{msg: "dup"}, "unable to execute SQL")
	untagged := classifyingDB().WrapSQLError(errors.New("dup"), "unable to execute SQL")

	if got, want := countFrames(t, tagged), countFrames(t, untagged); got != want {
		t.Errorf("the tagged branch printed %d frames under %%+v, the untagged one %d; "+
			"tagging must not add a stack", got, want)
	}
}

// TestWrapSQLError_SurvivesTheDataLayersOwnWrapping is what makes the handler's errors.Is safe.
// Nothing calls ExecSql directly: CreateUser wraps its result, the user creator wraps that, and the
// handler sees the outermost. A sentinel that stopped being reachable one layer up would leave the
// 409 unreachable while every test at this seam still passed.
func TestWrapSQLError_SurvivesTheDataLayersOwnWrapping(t *testing.T) {
	err := classifyingDB().WrapSQLError(&driverUniqueError{msg: "dup"}, "unable to execute SQL")
	err = errs.Wrap(err, "unable to insert user")
	err = errs.Wrap(err, "unable to create user")

	if !errors.Is(err, ErrUniqueViolation) {
		t.Errorf("the sentinel must survive the wrapping between here and a handler; err = %v", err)
	}
}

// TestWrapSQLError_DoesNotTagUnrelatedFailures guards the direction that would be worst to get
// wrong: answering 409 to a caller whose write failed for a reason retrying will not fix.
func TestWrapSQLError_DoesNotTagUnrelatedFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"sql.ErrNoRows", sql.ErrNoRows},
		{"a plain error naming a unique constraint", errors.New("UNIQUE constraint failed: users.email")},
		{"a connection failure", errors.New("driver: bad connection")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := classifyingDB().WrapSQLError(tc.err, "unable to execute SQL")
			if errors.Is(err, ErrUniqueViolation) {
				t.Errorf("WrapSQLError tagged %v, which the classifier did not recognise", tc.err)
			}
		})
	}
}

// countFrames counts the frames %+v printed, by counting the "\n\t<file>:<line>" lines errs' layout
// emits exactly one of per frame. A second captured stack shows up as roughly twice the frames,
// which is the thing being guarded against; the count itself is compared against another error
// built at the same depth rather than against a literal, because asserting on file paths and line
// numbers drifts with every edit.
func countFrames(t *testing.T, err error) int {
	t.Helper()
	return strings.Count(fmt.Sprintf("%+v", err), "\n\t")
}
