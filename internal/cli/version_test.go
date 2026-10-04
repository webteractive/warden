package cli

import (
	"strings"
	"testing"
)

// Which spelling a caller reaches for is not predictable — an install check, a
// bug report and a support thread each try a different one — and warden used to
// answer none of them: `warden --version` said "unknown flag", which reads as a
// broken binary to every script that asks. All three have to work.
func TestEverySpellingOfTheVersionQuestionAnswers(t *testing.T) {
	for _, args := range [][]string{
		{"--version"},
		{"-v"},
		{"version"},
	} {
		out, errw, code := run(t, args...)
		if code != 0 {
			t.Errorf("%v: code = %d, want 0 — asking the version is a successful answer, "+
				"not a diagnostic: %s", args, code, errw)
		}
		// Scripts read stdout. Printing to stderr breaks the main caller.
		if !strings.HasPrefix(out, "warden ") {
			t.Errorf("%v: stdout = %q, want it to start with %q", args, out, "warden ")
		}
		if strings.TrimSpace(out) == "warden" {
			t.Errorf("%v: printed a name with no version after it: %q", args, out)
		}
		if errw != "" {
			t.Errorf("%v: wrote to stderr: %q", args, errw)
		}
	}
}

// The three spellings must not drift into reporting different things.
func TestTheVersionSpellingsAgree(t *testing.T) {
	flagOut, _, _ := run(t, "--version")
	shortOut, _, _ := run(t, "-v")
	subOut, _, _ := run(t, "version")

	if flagOut != shortOut || flagOut != subOut {
		t.Errorf("spellings disagree:\n --version %q\n -v        %q\n version   %q",
			flagOut, shortOut, subOut)
	}
}
