package prompt

import (
	"errors"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFakeApprovesByDefault(t *testing.T) {
	if err := (Fake{}).Confirm("public", "FOO_KEY", "/tmp/.env.schema", true); err != nil {
		t.Errorf("err = %v, want nil", err)
	}
}

func TestFakeCanSimulateADeclinedConfirmation(t *testing.T) {
	p := Fake{ConfirmErr: ErrCancelled}
	if err := p.Confirm("public", "FOO_KEY", "/tmp/.env.schema", true); !errors.Is(err, ErrCancelled) {
		t.Errorf("err = %v, want ErrCancelled", err)
	}
}

func TestFakeReportsWhenItWasAsked(t *testing.T) {
	// Callers must be able to prove a refusal happened *before* the user was
	// bothered. Without this hook, "refused early" and "refused late" look the same.
	var gotClass, gotKey string
	var gotRetype bool
	p := Fake{OnConfirm: func(class, key, _ string, retypeKey bool) {
		gotClass, gotKey, gotRetype = class, key, retypeKey
	}}
	_ = p.Confirm("public", "FOO_KEY", "/tmp/.env.schema", true)
	if gotClass != "public" || gotKey != "FOO_KEY" || !gotRetype {
		t.Errorf("OnConfirm saw (%q, %q, %v), want (public, FOO_KEY, true)", gotClass, gotKey, gotRetype)
	}
}

func TestRefusingConfirmNamesTheExactCommandToRun(t *testing.T) {
	err := Refusing{}.Confirm("public", "FOO_KEY", "/tmp/.env.schema", true)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if !strings.Contains(err.Error(), "warden classify FOO_KEY --set public") {
		t.Errorf("error should quote the command to run, got: %v", err)
	}
}

func TestRetypedKeyMustMatchExactly(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr error
	}{
		{"exact match approves", "FOO_KEY\n", nil},
		{"surrounding space is tolerated", "  FOO_KEY \n", nil},
		{"wrong key is a refusal", "BAR_KEY\n", ErrCancelled},
		{"case must match", "foo_key\n", ErrCancelled},
		{"prefix is not enough", "FOO\n", ErrCancelled},
		{"empty is a refusal", "\n", ErrCancelled},
		{"timeout is a refusal", timeoutSentinel + "\n", ErrCancelled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkRetyped(tc.raw, "FOO_KEY"); !errors.Is(err, tc.wantErr) {
				t.Errorf("checkRetyped(%q) = %v, want %v", tc.raw, err, tc.wantErr)
			}
		})
	}
}

func TestRetypeDialogShowsTypingAndNamesTheConsequence(t *testing.T) {
	s := buildConfirmScript("public", "FOO_KEY", "/tmp/.env.schema", 60, true)
	if strings.Contains(s, "hidden answer") {
		t.Error("a key name is not a secret — hiding it would stop the user checking their own typing")
	}
	if !strings.Contains(s, "default answer") {
		t.Error("the retype variant needs a text field")
	}
	if !strings.Contains(s, "FOO_KEY") {
		t.Error("the dialog must name the key being reclassified")
	}
	if !strings.Contains(s, "public") {
		t.Error("the dialog must say which class is being recorded")
	}
	if !strings.Contains(s, "giving up after 60") {
		t.Error("the dialog must time out")
	}
}

func TestPlainConfirmDialogHasNoTextFieldAndDefaultsToCancel(t *testing.T) {
	s := buildConfirmScript("secret", "FOO_KEY", "/tmp/.env.schema", 60, false)
	if strings.Contains(s, "default answer") {
		t.Error("the plain variant must not ask for typing")
	}
	if !strings.Contains(s, `default button "Cancel"`) {
		t.Error("Return must not authorise — the safe button has to be the default")
	}
	if !strings.Contains(s, "FOO_KEY") {
		t.Error("the dialog must still name the key")
	}
}

// The other script tests check the text we generate. This one checks that macOS
// can actually parse it: every assertion above would still pass on a script with
// a syntax error, which would make the dialog fail only on a real user's Mac.
// osacompile parses without displaying anything.
func TestConfirmScriptCompilesAsAppleScript(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("AppleScript is macOS only")
	}
	bin, err := exec.LookPath("osacompile")
	if err != nil {
		t.Skip("osacompile unavailable")
	}

	for _, tc := range []struct {
		name   string
		script string
	}{
		{"retype", buildConfirmScript("public", "FOO_KEY", "/tmp/.env.schema", 60, true)},
		{"plain", buildConfirmScript("secret", "FOO_KEY", "/tmp/.env.schema", 60, false)},
		{"quoted key", buildConfirmScript("public", `WEIRD"KEY`, `/tmp/my "dir"/.env.schema`, 60, true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "s.scpt")
			cmd := exec.Command(bin, "-o", out, "-e", tc.script)
			if b, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("script does not compile: %v\n%s\n--- script ---\n%s", err, b, tc.script)
			}
		})
	}
}

// AskSecret's dialog is JXA, not AppleScript, so it compiles as JavaScript.
func TestSecretDialogCompiles(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("JXA is macOS only")
	}
	bin, err := exec.LookPath("osacompile")
	if err != nil {
		t.Skip("osacompile unavailable")
	}
	out := filepath.Join(t.TempDir(), "s.scpt")
	cmd := exec.Command(bin, "-l", "JavaScript", "-o", out, "-e", secretDialog)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("script does not compile: %v\n%s", err, b)
	}
}

func TestConfirmScriptEscapesQuotes(t *testing.T) {
	s := buildConfirmScript("public", `WEIRD"KEY`, `/tmp/my "dir"/.env.schema`, 60, true)
	if strings.Contains(s, `"WEIRD"KEY"`) {
		t.Error("unescaped quote would break the AppleScript")
	}
}
