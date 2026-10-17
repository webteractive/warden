package prompt

import (
	"errors"
	"strings"
	"testing"
)

func TestFakeReturnsItsValue(t *testing.T) {
	p := Fake{Value: "hunter2"}
	got, err := p.AskSecret("DB_PASSWORD", "/tmp/.env")
	if err != nil {
		t.Fatal(err)
	}
	if got.Expose() != "hunter2" {
		t.Errorf("got %q", got.Expose())
	}
}

func TestFakeCanSimulateCancellation(t *testing.T) {
	p := Fake{Err: ErrCancelled}
	if _, err := p.AskSecret("K", "/tmp/.env"); !errors.Is(err, ErrCancelled) {
		t.Errorf("err = %v, want ErrCancelled", err)
	}
}

func TestRefusingPrompterExplainsWhatToDo(t *testing.T) {
	_, err := Refusing{}.AskSecret("DB_PASSWORD", "/tmp/.env")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if !strings.Contains(err.Error(), "DB_PASSWORD") {
		t.Error("the error should name the key so the user knows what to set")
	}
}

func TestParseOsascriptOutput(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    string
		wantErr error
	}{
		{"plain value", "hunter2\n", "hunter2", nil},
		{"value with spaces", "two words\n", "two words", nil},
		{"pasted trailing newline", "tok\r\n\n", "tok", nil},
		{"multi-line value keeps inner breaks", "-----BEGIN-----\nabc\n-----END-----\n", "-----BEGIN-----\nabc\n-----END-----", nil},
		{"timeout sentinel", timeoutSentinel + "\n", "", ErrCancelled},
		{"empty means cancel", "\n", "", ErrCancelled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseOsascript(tc.raw)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if got.Expose() != tc.want {
				t.Errorf("got %q, want %q", got.Expose(), tc.want)
			}
		})
	}
}

func TestOsascriptOutputIsNeverEmbeddedInAnError(t *testing.T) {
	// A parse failure must not quote the raw output back — that output is the
	// secret the user just typed.
	_, err := parseOsascript(timeoutSentinel + "\n")
	if err != nil && strings.Contains(err.Error(), timeoutSentinel) {
		t.Error("error text must not echo osascript output")
	}
}

func TestSecretDialogTakesKeyAndPathFromItsEnvironment(t *testing.T) {
	// A key that reads as an osascript option must never reach its command line.
	key, path := `-e "KEY'`, `/tmp/my "dir"/.env`
	env := dialogEnv([]string{"HOME=/h"}, key, path)
	want := []string{"HOME=/h", "WARDEN_DIALOG_KEY=" + key, "WARDEN_DIALOG_PATH=" + path}
	if strings.Join(env, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("env = %q, want %q", env, want)
	}
	for _, name := range []string{"WARDEN_DIALOG_KEY", "WARDEN_DIALOG_PATH"} {
		if !strings.Contains(secretDialog, name) {
			t.Errorf("secret dialog does not read %s", name)
		}
	}
}

func TestSecretDialogHidesInASecureFieldUntilRevealed(t *testing.T) {
	for _, want := range []string{
		"NSSecureTextField",   // hidden: secure input, no copy, no AX value
		"NSTextView",          // revealed: a textarea, so a long token wraps
		"NSWindowSharingNone", // never screen-captured
		"'Reveal'", "'Hide'",
		"shown ? scroll : secure",
	} {
		if !strings.Contains(secretDialog, want) {
			t.Errorf("secret dialog is missing %s", want)
		}
	}
	if strings.Contains(secretDialog, "clearColor") {
		t.Error("hiding must be a secure field, not invisible text")
	}
}
