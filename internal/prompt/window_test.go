package prompt

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/webteractive/warden/internal/dialog"
)

// fakeDialogEnv tells the test binary, started as the dialog child, how to
// behave. Window starts os.Executable, which under `go test` is this binary.
const fakeDialogEnv = "WARDEN_TEST_FAKE_DIALOG"

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == dialog.Arg {
		fakeDialog()
	}
	os.Exit(m.Run())
}

func fakeDialog() {
	switch os.Getenv(fakeDialogEnv) {
	case "save":
		os.Stdout.WriteString("hunter2")
		os.Exit(dialog.ExitSaved)
	case "echo":
		// Proves what reached the child, and how: argv must be the marker alone.
		os.Stdout.WriteString(strings.Join(os.Args[1:], " ") + "|" + os.Getenv(dialog.EnvKey) + "|" + os.Getenv(dialog.EnvPath))
		os.Exit(dialog.ExitSaved)
	case "empty":
		os.Exit(dialog.ExitSaved)
	case "cancel":
		os.Exit(dialog.ExitCancelled)
	case "hang":
		time.Sleep(time.Minute)
	}
	os.Exit(dialog.ExitUnavailable)
}

func TestWindowReturnsTheSavedValue(t *testing.T) {
	t.Setenv(fakeDialogEnv, "save")
	got, err := Window{Prompter: Refusing{}}.AskSecret("K", "/tmp/.env")
	if err != nil || got.Expose() != "hunter2" {
		t.Fatalf("got %q, %v", got.Expose(), err)
	}
}

func TestWindowPassesKeyAndPathOnlyThroughTheEnvironment(t *testing.T) {
	t.Setenv(fakeDialogEnv, "echo")
	key, path := "-e", `/tmp/my "dir"/.env`
	got, err := Window{Prompter: Refusing{}}.AskSecret(key, path)
	if err != nil {
		t.Fatal(err)
	}
	if want := dialog.Arg + "|" + key + "|" + path; got.Expose() != want {
		t.Errorf("child saw %q, want %q", got.Expose(), want)
	}
}

func TestWindowCancelIsCancelled(t *testing.T) {
	t.Setenv(fakeDialogEnv, "cancel")
	if _, err := (Window{Prompter: Fake{Value: "fallback"}}).AskSecret("K", "/tmp/.env"); !errors.Is(err, ErrCancelled) {
		t.Fatalf("err = %v, want ErrCancelled (and no fallback)", err)
	}
}

func TestWindowEmptyValueIsCancelled(t *testing.T) {
	t.Setenv(fakeDialogEnv, "empty")
	if _, err := (Window{Prompter: Refusing{}}).AskSecret("K", "/tmp/.env"); !errors.Is(err, ErrCancelled) {
		t.Fatalf("err = %v, want ErrCancelled", err)
	}
}

func TestWindowFallsBackWhenNoWindowOpens(t *testing.T) {
	t.Setenv(fakeDialogEnv, "unavailable")
	got, err := Window{Prompter: Fake{Value: "from-tty"}}.AskSecret("K", "/tmp/.env")
	if err != nil || got.Expose() != "from-tty" {
		t.Fatalf("got %q, %v; want the fallback's answer", got.Expose(), err)
	}
}

func TestWindowTimesOut(t *testing.T) {
	t.Setenv(fakeDialogEnv, "hang")
	start := time.Now()
	_, err := Window{Prompter: Fake{Value: "fallback"}, Timeout: 300 * time.Millisecond}.AskSecret("K", "/tmp/.env")
	if !errors.Is(err, ErrCancelled) || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v, want a timeout", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Error("the timeout did not stop the child")
	}
}

func TestWindowAnswersConfirmThroughItsFallback(t *testing.T) {
	called := false
	w := Window{Prompter: Fake{OnAction: func(string, string, string) { called = true }}}
	if err := w.ConfirmAction("remove", "K", "/tmp/.env"); err != nil || !called {
		t.Fatalf("err = %v, called = %v", err, called)
	}
}
