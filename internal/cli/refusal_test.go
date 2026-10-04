package cli

import (
	"strings"
	"testing"
)

// The refusal an agent hits when it already holds a credential.
//
// It used to name only --secret, which is the wrong advice here: reaching this
// refusal means the value was passed as an argument, so it is already in argv
// and shell history and no prompt can take that back. Agents given advice that
// plainly does not fit their situation did not follow it — they wrote the file
// by hand. Both commands have to be named, along with the test for choosing.
func TestRefusingASecretWriteNamesBothChannels(t *testing.T) {
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n"})

	out, errw, code := run(t, "set", "DB_PASSWORD", "hunter2", "--project", dir)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	for _, want := range []string{
		"warden set --exposed DB_PASSWORD",
		"warden set --secret DB_PASSWORD",
		"argv",
		"already had it",
		"relaying a value the user holds",
		"not a way around this",
	} {
		if !strings.Contains(errw, want) {
			t.Errorf("the refusal should say %q:\n%s", want, errw)
		}
	}
	if strings.Contains(out+errw, "hunter2") {
		t.Error("the refusal echoed the value it is refusing to store")
	}
	if got := readEnv(t, dir); got != "APP_NAME=Warden\n" {
		t.Errorf("the file changed despite the refusal: %q", got)
	}
}

// A public key handed a credential-shaped value is a different problem with
// different advice, and conflating the two produces a non-sequitur: warden would
// have taken this key happily with an ordinary value, so "use --secret" answers
// a question nobody asked. What is usually true is that the key is misclassified.
func TestRefusingACredentialShapedValueGivesItsOwnAdvice(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n"})

	out, errw, code := run(t, "set", "APP_NAME", "sk_live_51H8xLpJ2eZvKYlo2C0", "--project", dir)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(errw, "credential shape") {
		t.Errorf("the refusal should say the value is what triggered it:\n%s", errw)
	}
	if !strings.Contains(errw, "warden classify APP_NAME") {
		t.Errorf("the refusal should point at the classification:\n%s", errw)
	}
	// The value-shape case must not be sent to --secret. It is a public key: the
	// secret channel would store a value warden already said belongs elsewhere.
	if strings.Contains(errw, "warden set --secret") {
		t.Errorf("a value-shape refusal must not recommend --secret:\n%s", errw)
	}
	if strings.Contains(out+errw, "sk_live_51H8xLpJ2eZvKYlo2C0") {
		t.Error("the refusal echoed the credential it is refusing to store")
	}
}

// --exposed exists so a burned value can be recorded honestly, which only works
// if the refusal that sends callers there actually leads somewhere. This walks
// the path the message describes.
func TestTheRefusalsAdviceActuallyWorks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n"})

	if _, _, code := run(t, "set", "DB_PASSWORD", "hunter2", "--project", dir); code != 2 {
		t.Fatal("expected the refusal that sets up this test")
	}
	out, errw, code := run(t, "set", "--exposed", "DB_PASSWORD", "hunter2", "--project", dir)
	if code != 0 {
		t.Fatalf("the command the refusal recommends failed: code = %d: %s", code, errw)
	}
	if !strings.Contains(out, "exposed") {
		t.Errorf("the confirmation should record the channel: %q", out)
	}
	// The key stays secret: --exposed describes how the value got in, not who
	// may read it.
	if _, _, code := run(t, "get", "DB_PASSWORD", "--project", dir); code != 2 {
		t.Errorf("get code = %d, want 2 — --exposed must not make the key readable", code)
	}
}
