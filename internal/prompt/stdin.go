package prompt

import (
	"errors"
	"io"

	"github.com/webteractive/warden/internal/secret"
)

// Stdin supplies the value from the process's standard input.
//
// This is the one non-interactive channel warden cannot make any promise about.
// A file is opened by warden and a generated value is minted by warden, so in
// both cases the caller demonstrably never held the value. A pipe is written by
// whoever built the pipeline — if that is an agent, the agent had the value
// before warden did, and no amount of care on this side changes that.
//
// It is supported because a human at their own terminal is not that caller, and
// for them the convenience is real. Being the weakest channel, it is the only
// one that must be asked for by name: see the --stdin flag. The CLI also names
// it in its output, so the weaker guarantee is visible in a transcript rather
// than assumed.
type Stdin struct {
	Prompter
	In io.Reader
}

func (s Stdin) AskSecret(string, string) (secret.Secret, error) {
	raw, err := io.ReadAll(s.In)
	if err != nil {
		// Deliberately not wrapped. The bytes on this reader are the secret, and
		// a reader is free to put anything in its error — including what it was
		// mid-way through reading. There is nothing diagnostic in the cause here
		// that is worth that risk: the caller knows it piped something in, and
		// the only useful fact is that the read did not finish.
		return "", errors.New("reading standard input failed")
	}
	v, err := fromRaw(string(raw))
	if errors.Is(err, ErrCancelled) {
		// fromRaw reports an empty value as a cancellation, which is right for a
		// dialog somebody dismissed and wrong here. Nothing was dismissed:
		// --stdin was passed and the descriptor delivered nothing. Reporting
		// that as "cancelled" is what taught callers to give up — the message
		// read as though the user had refused.
		return "", ErrNoValue
	}
	return v, err
}
