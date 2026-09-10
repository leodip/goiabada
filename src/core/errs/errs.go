// Package errs is the one way this tree constructs an error.
//
// Three rules, and they are what every other package here can rely on:
//
//  1. Construct through this package. New, Errorf, Wrap, Wrapf, WithStack and Join are the whole
//     surface; stdlib errors.New and fmt.Errorf are refused in production code by
//     testutil.AssertNoLegacyErrors, except for a package-level sentinel, which must stay plain
//     because a stack captured at init would masquerade as the origin of every error wrapping it.
//  2. Match with errors.Is and errors.As. Every value built here unwraps, so a sentinel and a
//     typed error stay reachable however many layers wrapped them. A bare type assertion does not
//     see through a wrapper and is a bug waiting for the first caller who wraps.
//  3. One stack per error tree, and it is the leftmost origin's. A constructor captures frames
//     only when the value it just built has none anywhere; a wrapper over something already
//     stacked carries no frames of its own and prints the origin's. This is the point of the
//     package: github.com/pkg/errors captured a new stack at every call, so one failure crossing
//     the data layer, a service and a handler printed three stacks and 27 lines under %+v, all of
//     them the same failure. Undo it and every log line for a 500 triples in size while saying
//     less.
//
// %+v prints the message and then one "func\n\tfile:line" pair per frame, which is
// github.com/pkg/errors' own layout: the servers run slog's default handler, which formats an
// error attribute with %+v, so log readers keep the shape they had. %v and Error() print the
// message alone. There is no LogValue: a JSON handler would then print the message only, which is
// slog's convention, and the 500 writers print the stack explicitly regardless.
//
// This package imports nothing outside the standard library, deliberately: it sits below models
// and data, so anything it imported could never construct an error through it (#279).
package errs

import (
	"errors"
	"fmt"
	"io"
	"runtime"
)

// withStack carries a message chain and, when it is the tree's origin, the program counters of
// the frames that reached it. A wrapper over an already-stacked tree is a withStack with a nil
// pcs: it owns no frames, and its Format walks down to the one that does.
type withStack struct {
	err error
	pcs []uintptr
}

func (e *withStack) Error() string { return e.err.Error() }

func (e *withStack) Unwrap() error { return e.err }

// Format prints the message for %v and %s, and for %+v the message followed by the frames of the
// tree's owner. A tree with no owner prints its message and nothing else, never a synthetic ":0"
// frame.
func (e *withStack) Format(s fmt.State, verb rune) {
	io.WriteString(s, e.err.Error())
	if verb != 'v' || !s.Flag('+') {
		return
	}
	ws := owner(e)
	if ws == nil {
		return
	}
	frames := runtime.CallersFrames(ws.pcs)
	for {
		f, more := frames.Next()
		fmt.Fprintf(s, "\n%s\n\t%s:%d", f.Function, f.File, f.Line)
		if !more {
			break
		}
	}
}

// owner walks the error tree depth-first in Unwrap order, the single Unwrap() error first and
// then each element of Unwrap() []error left to right, and returns the first withStack carrying
// frames. That is the order errors.Is and errors.As use, so under a join or a multi-%w Errorf the
// leftmost stacked branch owns the tree's one stack. A log line therefore stays one stack long
// however many failures were joined into it.
func owner(err error) *withStack {
	for err != nil {
		if ws, ok := err.(*withStack); ok && ws.pcs != nil {
			return ws
		}
		switch u := err.(type) {
		case interface{ Unwrap() error }:
			err = u.Unwrap()
		case interface{ Unwrap() []error }:
			for _, child := range u.Unwrap() {
				if ws := owner(child); ws != nil {
					return ws
				}
			}
			return nil
		default:
			return nil
		}
	}
	return nil
}

// callers records the frames above it, skipping runtime.Callers, callers itself, and skip more.
// The skip is passed in rather than fixed so an exported constructor's first frame is its own
// caller whatever the depth of the internal call layers between them: a hard-coded
// runtime.Callers(3) is right for one call shape and silently wrong for the next one added.
func callers(skip int) []uintptr {
	var pcs [32]uintptr
	n := runtime.Callers(2+skip, pcs[:])
	return pcs[:n]
}

// stack is the rule every constructor applies to the value it has just built, and the single
// place rule 3 lives. skip counts the frames between the exported constructor and its caller.
func stack(err error, skip int) error {
	if err == nil {
		return nil
	}
	// Already ours, and already answering for the tree: nothing to add.
	if _, ok := err.(*withStack); ok {
		return err
	}
	// A stdlib wrapper or a join sitting over a stacked branch. Capturing here would record the
	// wrapper's frames as the origin's, and returning it bare would hide the origin from %+v,
	// because a plain fmt wrapper has no Format that reaches down. A frameless withStack keeps
	// the message and restores the reach.
	if owner(err) != nil {
		return &withStack{err: err}
	}
	return &withStack{err: err, pcs: callers(skip + 2)}
}

// New returns an error with msg and the caller's stack. It is stdlib errors.New plus rule 3.
func New(msg string) error { return &withStack{err: errors.New(msg), pcs: callers(1)} }

// Errorf formats an error the way fmt.Errorf does, %w included, and applies rule 3: a chain that
// already carries a stack inherits it rather than capturing a second one.
func Errorf(format string, a ...any) error { return stack(fmt.Errorf(format, a...), 0) }

// Wrap returns an error prefixing msg to err's message, "msg: err", which is byte-identical to
// github.com/pkg/errors' text. Nil in, nil out: 24 call sites return Wrap unconditionally and
// rely on it.
func Wrap(err error, msg string) error {
	if err == nil {
		return nil
	}
	return stack(fmt.Errorf("%s: %w", msg, err), 0)
}

// Wrapf is Wrap with a formatted message. It formats and wraps directly rather than calling Wrap,
// so the frame skip is the same one every other exported constructor uses.
func Wrapf(err error, format string, a ...any) error {
	if err == nil {
		return nil
	}
	return stack(fmt.Errorf("%s: %w", fmt.Sprintf(format, a...), err), 0)
}

// WithStack attaches the caller's stack to err when its tree has none, and is otherwise the
// identity. Nil in, nil out. It is what the 500 writers call on whatever they are handed, so a
// bare stdlib error still logs with a stack.
func WithStack(err error) error { return stack(err, 0) }

// Join is errors.Join under rule 3, so a join of bare errors is stacked where it was made rather
// than wherever a writer first saw it. Nil in, nil out, as errors.Join is.
func Join(errs ...error) error { return stack(errors.Join(errs...), 0) }
