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

func TestSecretDialogTakesKeyAndPathAsArguments(t *testing.T) {
	key, path := `WEIRD"KEY'`, `/tmp/my "dir"/.env`
	args := osascriptArgs(key, path)
	if got := args[len(args)-2:]; got[0] != key || got[1] != path {
		t.Errorf("key and path must reach the script verbatim as arguments, got %q", got)
	}
	if strings.Contains(secretDialog, "WEIRD") {
		t.Error("the key must not be spliced into the script")
	}
}

func TestSecretDialogIsAHiddenTextareaWithReveal(t *testing.T) {
	for _, want := range []string{
		"NSTextView", // a textarea, so a long token wraps
		"clearColor", // hidden until revealed
		"'Reveal'", "'Hide'",
	} {
		if !strings.Contains(secretDialog, want) {
			t.Errorf("secret dialog is missing %s", want)
		}
	}
}
