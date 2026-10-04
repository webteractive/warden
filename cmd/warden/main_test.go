package main

import (
	"os"
	"testing"
)

// canCarryAValue answers a narrower question than its predecessor did, and the
// narrowing is the fix for a real break.
//
// warden used to decide from this mode alone whether a value had been piped in,
// and a named pipe was taken as proof. It is not: spawning a child with
// stdin=PIPE is how process runners work, so every agent that ran
// `warden set --secret KEY` handed warden an empty pipe and got a refusal
// instead of a prompt. Selecting the channel is now the --stdin flag's job, and
// all this decides is whether reading would work at all.
//
// So a pipe and a regular file are both allowed here — neither can be reached
// without --stdin now — and what must stay out are the descriptors where a read
// is actively harmful or pointless.
func TestWhichStdinAValueCouldBeReadFrom(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode os.FileMode
		want bool
	}{
		{"a pipe, as in `cmd | warden ... --stdin`", os.ModeNamedPipe, true},

		// `warden ... --stdin < creds.txt`. This was excluded when the mode
		// alone selected the channel, because `./deploy.sh < input` gives every
		// command the script runs a regular-file stdin and warden would have
		// eaten the script's input. --stdin has to be typed, so that accident
		// is no longer reachable and the redirect can be honoured.
		{"a redirected regular file", 0, true},

		// A caller that wired up a socket, which is what some agent harnesses
		// hand a child. Allowed for the same reason: --stdin still has to be
		// passed before anything reads it.
		{"a socket", os.ModeSocket, true},

		// This channel is io.ReadAll with no echo control. Reading a terminal
		// here would print the credential on screen as it was typed, which is
		// the one thing every channel in internal/prompt exists to prevent — a
		// terminal gets the prompt instead.
		{"a terminal, which would echo the value", os.ModeCharDevice | os.ModeDevice, false},

		// Carries nothing. Refusing up front beats reading it and reporting an
		// empty value.
		{"/dev/null", os.ModeCharDevice, false},

		// Reading one fails everywhere, and the error says nothing actionable.
		{"a directory", os.ModeDir, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := canCarryAValue(tc.mode); got != tc.want {
				t.Errorf("canCarryAValue(%v) = %v, want %v", tc.mode, got, tc.want)
			}
		})
	}
}
