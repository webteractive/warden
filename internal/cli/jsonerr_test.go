package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

type jsonError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func decodeError(t *testing.T, errw string) jsonError {
	t.Helper()
	var e jsonError
	if err := json.Unmarshal([]byte(errw), &e); err != nil {
		t.Fatalf("stderr is not a JSON error (%v): %q", err, errw)
	}
	return e
}

// A program asking with --json has to tell "this project has no .env" apart
// from "warden broke" without matching English. Both exit 3.
func TestJSONErrorsNameTheirCause(t *testing.T) {
	for _, command := range []string{"list", "doctor", "missing"} {
		t.Run(command, func(t *testing.T) {
			out, errw, code := run(t, command, "--json", "--project", t.TempDir())
			if code != 3 {
				t.Errorf("code = %d, want 3", code)
			}
			if out != "" {
				t.Errorf("stdout should be empty on an error, got %q", out)
			}
			e := decodeError(t, errw)
			if e.Error.Code != "no-env-file" || !strings.Contains(e.Error.Message, "no env file found") {
				t.Errorf("error = %+v", e.Error)
			}
		})
	}
}

func TestErrorsStayPlainTextWithoutJSON(t *testing.T) {
	_, errw, _ := run(t, "list", "--project", t.TempDir())
	if strings.HasPrefix(strings.TrimSpace(errw), "{") || !strings.Contains(errw, "no env file found") {
		t.Errorf("stderr = %q", errw)
	}
}

func TestJSONRefusalSaysRefused(t *testing.T) {
	dir := project(t, map[string]string{".env": "STRIPE_SECRET=sk_live_abc\n"})
	_, errw, code := run(t, "get", "STRIPE_SECRET", "--json", "--project", dir)
	if code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
	if e := decodeError(t, errw); e.Error.Code != "refused" {
		t.Errorf("error = %+v", e.Error)
	}
	if strings.Contains(errw, "sk_live_abc") {
		t.Error("a JSON error leaked the value")
	}
}

// has answers through its exit code and prints nothing; --json must not make a
// "no" talk.
func TestJSONKeepsASilentAnswerSilent(t *testing.T) {
	dir := project(t, map[string]string{".env": "A=1\n"})
	out, errw, code := run(t, "has", "ABSENT", "--json", "--project", dir)
	if code != 1 || out != "" || errw != "" {
		t.Errorf("code=%d out=%q err=%q", code, out, errw)
	}
}

func TestJSONUsageErrorsAreJSONToo(t *testing.T) {
	_, errw, code := run(t, "frobnicate", "--json")
	if code != 3 {
		t.Errorf("code = %d, want 3", code)
	}
	if e := decodeError(t, errw); e.Error.Code != "usage" {
		t.Errorf("error = %+v", e.Error)
	}
}
