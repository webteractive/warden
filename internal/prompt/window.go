package prompt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/webteractive/warden/internal/dialog"
	"github.com/webteractive/warden/internal/secret"
)

// Window asks through warden's own dialog window (internal/dialog): a
// multi-line field, masked until the user presses Reveal. The window runs in
// a child warden process; the value comes back down a pipe and nowhere else.
//
// The embedded Prompter answers Confirm and ConfirmAction, and takes AskSecret
// over when no window can be opened.
type Window struct {
	Prompter
	Timeout time.Duration
}

func (w Window) AskSecret(key, path string) (secret.Secret, error) {
	exe, err := os.Executable()
	if err != nil {
		return w.Prompter.AskSecret(key, path)
	}
	timeout := w.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, exe, dialog.Arg)
	cmd.Env = append(os.Environ(), dialog.EnvKey+"="+key, dialog.EnvPath+"="+path)
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return "", fmt.Errorf("dialog timed out: %w", ErrCancelled)
	}
	var exit *exec.ExitError
	switch {
	case err == nil:
		// Reported as is: the child already dropped trailing line breaks, and
		// a value is never quoted back into an error.
		if len(out) == 0 {
			return "", fmt.Errorf("empty value: %w", ErrCancelled)
		}
		return secret.Secret(out), nil
	case errors.As(err, &exit) && exit.ExitCode() == dialog.ExitCancelled:
		return "", ErrCancelled
	default:
		// No display after all, or a build without the window: ask the way
		// warden would have without it.
		return w.Prompter.AskSecret(key, path)
	}
}

// canOpenWindow reports whether this build has the dialog window and the
// session has a display to put it on.
func canOpenWindow() bool {
	if !dialog.Available {
		return false
	}
	switch runtime.GOOS {
	case "windows":
		return true
	case "darwin":
		// Served by Osascript until the window gains macOS's secure keyboard
		// input and capture exclusion.
		return false
	default:
		return os.Getenv("WAYLAND_DISPLAY") != "" || os.Getenv("DISPLAY") != ""
	}
}
