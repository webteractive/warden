package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// withUmask sets the process umask for the duration of a test and restores it
// after. Create calls Chmod precisely because OpenFile's mode is masked by this,
// so a test that does not control it cannot tell the two apart.
func withUmask(t *testing.T, mask int) {
	t.Helper()
	prev := syscall.Umask(mask)
	t.Cleanup(func() { syscall.Umask(prev) })
}

func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

// The whole reason the command exists: the file must arrive at 0600, whatever
// the umask of whoever ran it. A umask of 022 is the default on macOS and most
// Linux accounts, and it is what turns a fresh env file into one every other
// account on the machine can read.
func TestInitCreatesTheFileOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	withUmask(t, 0o022)

	out, errw, code := run(t, "init", "--project", dir)
	if code != 0 {
		t.Fatalf("code = %d: %s", code, errw)
	}
	path := filepath.Join(dir, ".env")
	if got := modeOf(t, path); got != 0o600 {
		t.Errorf("mode = %04o, want 0600", got)
	}
	if !strings.Contains(out, "created") || !strings.Contains(out, path) {
		t.Errorf("the output should name what it made: %q", out)
	}
}

// A file of credentials that other accounts can read is the finding doctor
// reports most often, and re-running init is the obvious thing to reach for
// once it does.
func TestInitTightensAnExistingLooseFile(t *testing.T) {
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n"})
	path := filepath.Join(dir, ".env")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	out, errw, code := run(t, "init", "--project", dir)
	if code != 0 {
		t.Fatalf("code = %d: %s", code, errw)
	}
	if got := modeOf(t, path); got != 0o600 {
		t.Errorf("mode = %04o, want 0600", got)
	}
	if !strings.Contains(out, "tightened") {
		t.Errorf("the output should say it changed the permissions: %q", out)
	}
	// Anything already written into a world-readable file has been readable all
	// along, and narrowing the mode now does not undo that. Saying so is the
	// difference between a fix and a false sense of one.
	if !strings.Contains(out, "exposed") {
		t.Errorf("the output should say the existing contents were exposed: %q", out)
	}
	if got := readEnv(t, dir); got != "APP_NAME=Warden\n" {
		t.Errorf("contents must be untouched, got %q", got)
	}
}

// Re-running is how this ends up in a setup script, so the no-op case has to be
// a success with nothing changed rather than a complaint.
func TestInitIsSafeToRerun(t *testing.T) {
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n"})

	out, errw, code := run(t, "init", "--project", dir)
	if code != 0 {
		t.Fatalf("code = %d: %s", code, errw)
	}
	if !strings.Contains(out, "already exists") {
		t.Errorf("expected the no-op to be reported plainly: %q", out)
	}
	if got := readEnv(t, dir); got != "APP_NAME=Warden\n" {
		t.Errorf("contents must be untouched, got %q", got)
	}
}

// The reading commands walk upward to find an .env, and init deliberately does
// not. `warden init` in a subdirectory means "make one here" — reporting that it
// had tightened the project root's file instead would be the wrong answer to the
// question actually asked.
func TestInitDoesNotAdoptAParentEnv(t *testing.T) {
	root := project(t, map[string]string{".env": "APP_NAME=Parent\n"})
	sub := filepath.Join(root, "service")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	out, errw, code := run(t, "init", "--project", sub)
	if code != 0 {
		t.Fatalf("code = %d: %s", code, errw)
	}
	if !strings.Contains(out, filepath.Join(sub, ".env")) {
		t.Errorf("init should report the file it made here: %q", out)
	}
	if _, err := os.Stat(filepath.Join(sub, ".env")); err != nil {
		t.Errorf("no file was created in the subdirectory: %v", err)
	}
}

func TestInitGlobalCreatesTheSecretsFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	_, errw, code := run(t, "init", "--global")
	if code != 0 {
		t.Fatalf("code = %d: %s", code, errw)
	}
	if got := modeOf(t, filepath.Join(home, ".secrets")); got != 0o600 {
		t.Errorf("mode = %04o, want 0600", got)
	}
}

func TestInitJSONReportsWhatItDid(t *testing.T) {
	dir := t.TempDir()

	out, errw, code := run(t, "init", "--project", dir, "--json")
	if code != 0 {
		t.Fatalf("code = %d: %s", code, errw)
	}
	var got struct {
		Path      string `json:"path"`
		Created   bool   `json:"created"`
		Tightened bool   `json:"tightened"`
		Mode      string `json:"mode"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not JSON: %v (%q)", err, out)
	}
	if !got.Created || got.Tightened {
		t.Errorf("created/tightened = %v/%v, want true/false", got.Created, got.Tightened)
	}
	if got.Mode != "0600" {
		t.Errorf("mode = %q, want %q", got.Mode, "0600")
	}
	if got.Path != filepath.Join(dir, ".env") {
		t.Errorf("path = %q", got.Path)
	}
}

// init creating the file is only useful if the rest of warden then works
// against it, so this walks the path a fresh project actually takes.
func TestInitProducesAFileTheOtherCommandsAccept(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := t.TempDir()

	if _, errw, code := run(t, "init", "--project", dir); code != 0 {
		t.Fatalf("init: %s", errw)
	}
	if _, errw, code := run(t, "set", "APP_NAME", "Warden", "--project", dir); code != 0 {
		t.Fatalf("set after init: %s", errw)
	}
	if got := readEnv(t, dir); !strings.Contains(got, "APP_NAME=Warden") {
		t.Errorf("value not written into the new file: %q", got)
	}
	if got := modeOf(t, filepath.Join(dir, ".env")); got != 0o600 {
		t.Errorf("mode after a write = %04o, want 0600", got)
	}
}
