package main

import (
	"fmt"
	"io"
)

// palette is the escape sequences the wizard's output is coloured with. The zero value colours
// nothing, which is what --no-color and an output that is not a terminal get. It is a value handed
// to what prints, where it was six package variables disableColors blanked in place (#430).
type palette struct {
	reset, red, green, yellow, cyan, bold string
}

var ansiColors = palette{
	reset:  "\033[0m",
	red:    "\033[31m",
	green:  "\033[32m",
	yellow: "\033[33m",
	cyan:   "\033[36m",
	bold:   "\033[1m",
}

// console is where the wizard writes what the operator reads, and in which colours.
type console struct {
	w io.Writer
	palette
}

// printf and println are the console's one way to write. A failed write to the terminal has no one
// left to report it to, so it is dropped here rather than at each of the calls.
func (c *console) printf(format string, args ...any) {
	_, _ = fmt.Fprintf(c.w, format, args...)
}

func (c *console) println(args ...any) {
	_, _ = fmt.Fprintln(c.w, args...)
}

func (c *console) success(format string, args ...any) {
	c.printf("%s✓%s %s\n", c.green, c.reset, fmt.Sprintf(format, args...))
}

func (c *console) warning(format string, args ...any) {
	c.printf("%s⚠️  Warning:%s %s\n", c.yellow, c.reset, fmt.Sprintf(format, args...))
}

func (c *console) fail(format string, args ...any) {
	c.printf("%s✗ Error:%s %s\n", c.red, c.reset, fmt.Sprintf(format, args...))
}

func (c *console) info(format string, args ...any) {
	c.printf("%s→%s %s\n", c.cyan, c.reset, fmt.Sprintf(format, args...))
}
