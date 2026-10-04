package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withGuardInput(t *testing.T, body string) {
	t.Helper()
	prev := GuardInput
	GuardInput = strings.NewReader(body)
	t.Cleanup(func() { GuardInput = prev })
}

func TestHookPrintsTheSettingsBlockAndWritesNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")

	out, _, code := run(t, "hook", "--settings", path)
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	if !strings.Contains(out, "PreToolUse") || !strings.Contains(out, "warden hook --guard") {
		t.Errorf("output should be the settings block:\n%s", out)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("the default mode must not write a settings file")
	}
}

func TestGuardBlocksAReadOfTheEnvFile(t *testing.T) {
	withGuardInput(t, `{"tool_name":"Bash","tool_input":{"command":"cat .env"}}`)

	_, errw, code := run(t, "hook", "--guard")
	if code != 2 {
		t.Errorf("code = %d, want 2 — refused by policy, which is also how a harness reads a block", code)
	}
	if !strings.Contains(errw, "warden has") {
		t.Errorf("the denial must name the replacement:\n%s", errw)
	}
}

func TestGuardAllowsAnUnrelatedCommand(t *testing.T) {
	withGuardInput(t, `{"tool_name":"Bash","tool_input":{"command":"ls -la"}}`)

	out, errw, code := run(t, "hook", "--guard")
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if out != "" || errw != "" {
		t.Errorf("an allowed call must be silent; got out=%q err=%q", out, errw)
	}
}

func TestGuardBlocksAReadToolOnTheEnvFile(t *testing.T) {
	withGuardInput(t, `{"tool_name":"Read","tool_input":{"file_path":"/p/.env"}}`)
	if _, _, code := run(t, "hook", "--guard"); code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
}

func TestGuardAllowsTheExampleFile(t *testing.T) {
	withGuardInput(t, `{"tool_name":"Read","tool_input":{"file_path":"/p/.env.example"}}`)
	if _, _, code := run(t, "hook", "--guard"); code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
}

// A malformed payload must not block every tool call in the session.
func TestGuardFailsOpenOnAnUnreadablePayload(t *testing.T) {
	withGuardInput(t, `not json`)
	if _, _, code := run(t, "hook", "--guard"); code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
}

func TestInstallRequiresAnExplicitYes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")

	out, _, code := run(t, "hook", "--install", "--settings", path)
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("nothing should be written without --yes")
	}
	if !strings.Contains(out, "--yes") {
		t.Errorf("the dry run must say how to apply it:\n%s", out)
	}
}

func TestInstallWritesTheEntryWithYes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")

	if _, _, code := run(t, "hook", "--install", "--yes", "--settings", path); code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	if _, _, code := run(t, "hook", "--check", "--settings", path); code != 0 {
		t.Errorf("--check = %d, want 0 after an install", code)
	}

	if _, _, code := run(t, "hook", "--uninstall", "--yes", "--settings", path); code != 0 {
		t.Fatalf("uninstall code = %d, want 0", code)
	}
	if _, _, code := run(t, "hook", "--check", "--settings", path); code != 1 {
		t.Errorf("--check = %d, want 1 after an uninstall", code)
	}
}

func TestHookRefusesAnUnsupportedTarget(t *testing.T) {
	out, errw, code := run(t, "hook", "--target", "emacs")
	if code != 3 {
		t.Errorf("code = %d, want 3", code)
	}
	if !strings.Contains(out+errw, "claude") {
		t.Errorf("the refusal should name what is supported:\n%s%s", out, errw)
	}
}

// The tool must never describe itself as a security boundary. Pinning a
// documentation invariant in a test is heavy-handed, and it is the only way one
// survives contact with future edits.
func TestHookHelpNeverClaimsItIsSecurity(t *testing.T) {
	out, errw, _ := run(t, "hook", "--help")
	text := strings.ToLower(out + errw)
	for _, banned := range []string{"secure", "security boundary", "prevents", "protects"} {
		if strings.Contains(text, banned) {
			t.Errorf("help claims more than the hook can deliver (%q):\n%s", banned, out+errw)
		}
	}
	if !strings.Contains(text, "speed bump") {
		t.Error("help should say plainly what this is")
	}
}

// The installed binary on PATH may predate the guard. Since the guard fails
// open, an older warden means every read is allowed while the user believes the
// hook is working — the exact false confidence --check exists to prevent.
func TestCheckReportsAnInstalledBinaryThatCannotRunTheGuard(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if _, _, code := run(t, "hook", "--install", "--yes", "--settings", path); code != 0 {
		t.Fatal("install failed")
	}

	prev := GuardProbe
	GuardProbe = func(string) error { return errors.New("unknown command \"hook\"") }
	t.Cleanup(func() { GuardProbe = prev })

	out, errw, code := run(t, "hook", "--check", "--settings", path)
	if code == 0 {
		t.Error("code = 0, want non-zero — the hook is installed but cannot run")
	}
	if !strings.Contains(out+errw, "too old") {
		t.Errorf("the report must say why it cannot work:\n%s%s", out, errw)
	}
}

func TestCheckReportsWardenMissingFromPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	prev := LookWarden
	LookWarden = func() (string, error) { return "", errors.New("not found") }
	t.Cleanup(func() { LookWarden = prev })

	out, errw, code := run(t, "hook", "--check", "--settings", path)
	if code == 0 {
		t.Error("code = 0, want non-zero")
	}
	if !strings.Contains(out+errw, "NOT on PATH") {
		t.Errorf("a denial naming a command that does not run is worse than no hook:\n%s%s", out, errw)
	}
}

func TestCheckPassesWhenTheGuardRuns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if _, _, code := run(t, "hook", "--install", "--yes", "--settings", path); code != 0 {
		t.Fatal("install failed")
	}
	prev := GuardProbe
	GuardProbe = func(string) error { return nil }
	t.Cleanup(func() { GuardProbe = prev })

	if _, _, code := run(t, "hook", "--check", "--settings", path); code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
}

// The payload used to be read for file_path and command only, so these three
// tools reached Decide with nothing in them and were always allowed.
func TestGuardReadsEveryFieldThatCanNameAFile(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"a notebook path", `{"tool_name":"NotebookEdit","tool_input":{"notebook_path":"/p/.env","new_source":"x"}}`},
		{"a grep path", `{"tool_name":"Grep","tool_input":{"pattern":"TOKEN","path":"/p/.env"}}`},
		{"a grep glob", `{"tool_name":"Grep","tool_input":{"pattern":"TOKEN","path":"/p","glob":".env*"}}`},
		{"a monitor command", `{"tool_name":"Monitor","tool_input":{"command":"tail -f .env","timeout_ms":1000,"description":"x"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withGuardInput(t, tc.body)
			if _, _, code := run(t, "hook", "--guard"); code != 2 {
				t.Errorf("code = %d, want 2", code)
			}
		})
	}
}

func guardJSON(t *testing.T, body string) (guardAnswer, string, int) {
	t.Helper()
	withGuardInput(t, body)
	out, errw, code := run(t, "hook", "--guard", "--json")
	var a guardAnswer
	if err := json.Unmarshal([]byte(out), &a); err != nil {
		t.Fatalf("stdout is not JSON (%v): %q", err, out)
	}
	return a, errw, code
}

// A caller that words its own messages — the Claude Code mod — needs the
// decision and its target without parsing prose. The exit codes stay what the
// settings hook already relies on.
func TestGuardJSONDescribesADenial(t *testing.T) {
	a, errw, code := guardJSON(t, `{"tool_name":"Bash","tool_input":{"command":"cat .env"}}`)
	if code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
	if a.Decision != "deny" || a.Target != "env" || !strings.Contains(a.Reason, "warden has") {
		t.Errorf("answer = %+v", a)
	}
	if errw != "" {
		t.Errorf("under --json the reason is on stdout only; stderr = %q", errw)
	}

	a, _, _ = guardJSON(t, `{"tool_name":"Read","tool_input":{"file_path":"/Users/x/.secrets"}}`)
	if a.Target != "secrets" {
		t.Errorf("target = %q, want secrets", a.Target)
	}
}

func TestGuardJSONDescribesAnAllow(t *testing.T) {
	a, errw, code := guardJSON(t, `{"tool_name":"Bash","tool_input":{"command":"ls"}}`)
	if code != 0 || a.Decision != "allow" || a.Target != "" || a.Reason != "" || errw != "" {
		t.Errorf("code=%d answer=%+v stderr=%q", code, a, errw)
	}
}

// Failing open is unchanged by --json; it only says so in a form a program reads.
func TestGuardJSONFailsOpenOnAnUnreadablePayload(t *testing.T) {
	a, _, code := guardJSON(t, `not json`)
	if code != 0 || a.Decision != "allow" {
		t.Errorf("code=%d answer=%+v", code, a)
	}
}

func TestGuardReadsTheLSPPath(t *testing.T) {
	withGuardInput(t, `{"tool_name":"LSP","tool_input":{"operation":"hover","filePath":"/p/.env","line":1,"character":1}}`)
	if _, _, code := run(t, "hook", "--guard"); code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
}

// ln -s .env notes.txt, then Read notes.txt: the name says nothing, where it
// lands says everything. The settings hook has no other way to see that.
func TestGuardJudgesASymlinkByWhereItLands(t *testing.T) {
	dir := project(t, map[string]string{".env": "A=1\n"})
	link := filepath.Join(dir, "notes.txt")
	if err := os.Symlink(filepath.Join(dir, ".env"), link); err != nil {
		t.Fatal(err)
	}
	withGuardInput(t, `{"tool_name":"Read","tool_input":{"file_path":"`+link+`"}}`)
	if _, _, code := run(t, "hook", "--guard"); code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
	withGuardInput(t, `{"tool_name":"Read","tool_input":{"file_path":"`+filepath.Join(dir, "missing.txt")+`"}}`)
	if _, _, code := run(t, "hook", "--guard"); code != 0 {
		t.Errorf("a path that resolves nowhere is judged by its name; code = %d", code)
	}
}
