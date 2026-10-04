package prompt

import (
	"errors"
	"strings"
	"testing"
)

func TestStdinReadsTheValue(t *testing.T) {
	got, err := Stdin{In: strings.NewReader("hunter2\n")}.AskSecret("K", "/tmp/.env")
	if err != nil {
		t.Fatal(err)
	}
	if got.Expose() != "hunter2" {
		t.Errorf("got %q, want %q", got.Expose(), "hunter2")
	}
}

func TestStdinSharesTheSameHygieneAsFile(t *testing.T) {
	// Same rules on every non-interactive channel, so the answer never depends
	// on which one the caller reached for.
	//
	// The exception is what an empty read reports. The other channels call it a
	// cancellation, which fits a dialog somebody dismissed; nothing was
	// dismissed here, so this one says the channel was empty instead. Calling it
	// "cancelled" told callers the user had refused, and a caller that believes
	// that stops retrying a command that would have worked.
	cases := []struct {
		name    string
		raw     string
		want    string
		wantErr error
	}{
		{"one trailing newline comes off", "hunter2\n", "hunter2", nil},
		{"CRLF comes off", "hunter2\r\n", "hunter2", nil},
		{"trailing spaces are kept", "hunter2 \n", "hunter2 ", nil},
		{"empty is no value, not a cancellation", "", "", ErrNoValue},
		{"newline only is no value", "\n", "", ErrNoValue},
		{"interior newlines kept", "a\nb\n", "a\nb", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Stdin{In: strings.NewReader(tc.raw)}.AskSecret("K", "/tmp/.env")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if got.Expose() != tc.want {
				t.Errorf("got %q, want %q", got.Expose(), tc.want)
			}
		})
	}
}

func TestStdinErrorsNeverEmbedTheInput(t *testing.T) {
	const canary = "cnry-9f3a1d-do-not-leak"
	_, err := Stdin{In: failingReader{canary}}.AskSecret("K", "/tmp/.env")
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), canary) {
		t.Errorf("error leaked stdin: %s", err)
	}
}

// failingReader fails mid-stream, carrying the canary in its error so a caller
// that wraps the read error verbatim would leak it.
type failingReader struct{ canary string }

func (f failingReader) Read([]byte) (int, error) {
	return 0, errors.New("read failed for " + f.canary)
}

// The two failures must stay distinguishable. If ErrNoValue ever wrapped
// ErrCancelled, every caller matching on cancellation would silently start
// treating an empty channel as a refusal again — which is the bug this
// separation exists to prevent.
func TestNoValueIsNotACancellation(t *testing.T) {
	_, err := Stdin{In: strings.NewReader("")}.AskSecret("K", "/tmp/.env")
	if !errors.Is(err, ErrNoValue) {
		t.Fatalf("err = %v, want ErrNoValue", err)
	}
	if errors.Is(err, ErrCancelled) {
		t.Error("ErrNoValue must not satisfy errors.Is(err, ErrCancelled)")
	}
}
