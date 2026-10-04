package main

import (
	"os"

	"github.com/webteractive/warden/internal/cli"
)

func main() {
	if in := valueBearingStdin(); in != nil {
		cli.SetStdin = in
	}
	// cli.Run writes any error message to stderr itself, so that error message
	// is covered by the canary leak test rather than escaping through main.
	os.Exit(cli.ExitCode(cli.Run(os.Args[1:], os.Stdout, os.Stderr)))
}

// valueBearingStdin returns os.Stdin when it is a descriptor `--stdin` could
// read a value from, and nil when it is not.
//
// Only the *shape* of stdin is decided here. Whether to read it at all is the
// --stdin flag's decision, and keeping those two apart is the whole point.
// warden used to infer the channel from a named pipe alone, which broke every
// caller that spawns it with stdin=PIPE — the ordinary way a process runner
// starts a child. Such a caller pipes no value, so `set --secret` read an empty
// pipe and refused instead of opening the dialog, and an agent that had been
// told to run `warden set --secret KEY` could not make it work at all. A pipe is
// evidence of how warden was spawned, never evidence that somebody piped a
// credential into it.
func valueBearingStdin() *os.File {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return nil
	}
	if !canCarryAValue(fi.Mode()) {
		return nil
	}
	return os.Stdin
}

// canCarryAValue reports whether a stdin of this mode is something a value could
// be read from. Split out from valueBearingStdin so the decision can be tested
// against each mode directly — a test binary's own stdin is whatever the harness
// gives it, which is exactly the ambiguity this function exists to resolve.
//
// Character devices are excluded, which covers both a terminal and /dev/null. A
// terminal must never be read on this channel: it is io.ReadAll with no echo
// control, so the value would appear on screen as it was typed — the one thing
// every channel in internal/prompt exists to prevent. A terminal gets the
// prompt. /dev/null carries nothing, and saying so up front beats reading it and
// then reporting an empty value.
//
// A directory is excluded because reading one fails on every platform, and the
// error it produces says nothing a caller can act on.
//
// Everything else is allowed — a pipe for `cmd | warden … --stdin`, a regular
// file for `warden … --stdin < creds.txt`, a socket for a caller that wired one
// up. None of them can be selected by accident now, and that is what makes
// accepting them safe: the mode alone no longer decides anything.
func canCarryAValue(mode os.FileMode) bool {
	return mode&os.ModeCharDevice == 0 && !mode.IsDir()
}
