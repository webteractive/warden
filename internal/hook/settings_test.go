package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func settings(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func decode(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("settings is not valid JSON: %v\n%s", err, b)
	}
	return out
}

func preToolUse(t *testing.T, path string) []any {
	t.Helper()
	hooks, _ := decode(t, path)["hooks"].(map[string]any)
	entries, _ := hooks["PreToolUse"].([]any)
	return entries
}

func TestInstallPreservesEverythingElseInTheFile(t *testing.T) {
	path := settings(t, `{
	  "model": "opus",
	  "hooks": {
	    "Stop": [{"hooks": [{"type": "command", "command": "afplay bell.aiff"}]}],
	    "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "other-guard"}]}]
	  }
	}`)

	if err := Install(path, "warden hook --guard"); err != nil {
		t.Fatal(err)
	}

	got := decode(t, path)
	if got["model"] != "opus" {
		t.Error("unrelated settings must survive")
	}
	hooks := got["hooks"].(map[string]any)
	if _, ok := hooks["Stop"]; !ok {
		t.Error("other hook events must survive")
	}
	if n := len(preToolUse(t, path)); n != 2 {
		t.Errorf("PreToolUse has %d entries, want 2 — the existing guard must survive", n)
	}
}

func TestInstallIsIdempotent(t *testing.T) {
	path := settings(t, `{}`)
	for i := 0; i < 3; i++ {
		if err := Install(path, "warden hook --guard"); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(preToolUse(t, path)); n != 1 {
		t.Errorf("PreToolUse has %d entries after three installs, want 1", n)
	}
}

func TestInstallCreatesAMissingSettingsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := Install(path, "warden hook --guard"); err != nil {
		t.Fatal(err)
	}
	if !Installed(path) {
		t.Error("Installed should report the entry it just wrote")
	}
}

// warden is not repairing somebody's JSON.
func TestInstallRefusesAMalformedSettingsFileWithoutTouchingIt(t *testing.T) {
	const body = `{"model": "opus",,,}`
	path := settings(t, body)

	if err := Install(path, "warden hook --guard"); err == nil {
		t.Fatal("expected a refusal")
	}
	b, _ := os.ReadFile(path)
	if string(b) != body {
		t.Errorf("the file was modified: %s", b)
	}
}

func TestUninstallRemovesOnlyWardensEntry(t *testing.T) {
	path := settings(t, `{"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "other-guard"}]}]}}`)
	if err := Install(path, "warden hook --guard"); err != nil {
		t.Fatal(err)
	}
	if _, err := Uninstall(path); err != nil {
		t.Fatal(err)
	}

	entries := preToolUse(t, path)
	if len(entries) != 1 {
		t.Fatalf("PreToolUse has %d entries, want 1", len(entries))
	}
	if !strings.Contains(mustJSON(t, entries[0]), "other-guard") {
		t.Error("uninstall removed the wrong entry")
	}
	if Installed(path) {
		t.Error("Installed should report false after uninstall")
	}
}

func TestInstalledIsFalseForAFileWithoutTheEntry(t *testing.T) {
	if Installed(settings(t, `{"hooks": {"PreToolUse": []}}`)) {
		t.Error("want false")
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The matcher selects which calls reach the guard at all. A tool Decide judges
// but the matcher leaves out is never asked about, so the two must agree.
func TestTheMatcherCoversEveryToolTheGuardJudges(t *testing.T) {
	tools := map[string]bool{}
	for _, name := range strings.Split(Matcher, "|") {
		tools[name] = true
	}
	for _, want := range []string{"Read", "Edit", "Write", "NotebookEdit", "Bash", "Grep", "Monitor", "LSP"} {
		if !tools[want] {
			t.Errorf("matcher %q leaves out %s", Matcher, want)
		}
	}
}
