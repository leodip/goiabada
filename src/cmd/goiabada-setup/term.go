package main

import (
	"fmt"
	"os"
)

// ANSI color codes
var (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func disableColors() {
	colorReset = ""
	colorRed = ""
	colorGreen = ""
	colorYellow = ""
	colorCyan = ""
	colorBold = ""
}

func printSuccess(format string, args ...interface{}) {
	fmt.Printf("%s✓%s %s\n", colorGreen, colorReset, fmt.Sprintf(format, args...))
}

func printWarning(format string, args ...interface{}) {
	fmt.Printf("%s⚠️  Warning:%s %s\n", colorYellow, colorReset, fmt.Sprintf(format, args...))
}

func printError(format string, args ...interface{}) {
	fmt.Printf("%s✗ Error:%s %s\n", colorRed, colorReset, fmt.Sprintf(format, args...))
}

func printInfo(format string, args ...interface{}) {
	fmt.Printf("%s→%s %s\n", colorCyan, colorReset, fmt.Sprintf(format, args...))
}
