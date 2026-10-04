package hook

import "testing"

func TestDecideOnFileReads(t *testing.T) {
	for _, tc := range []struct {
		name string
		tool string
		path string
		deny bool
	}{
		{"reading .env", "Read", "/p/.env", true},
		{"reading a scoped env file", "Read", "/p/.env.staging", true},
		{"reading ~/.secrets", "Read", "/Users/x/.secrets", true},
		{"editing .env", "Edit", "/p/.env", true},
		{"writing .env", "Write", "/p/.env", true},
		{"the example file is meant to be read", "Read", "/p/.env.example", false},
		{"the schema file is meant to be read", "Read", "/p/.env.schema", false},
		{"the central schema is meant to be read", "Read", "/Users/x/.warden/schema", false},
		{"an unrelated file", "Read", "/p/README.md", false},
		{"a file merely named like one", "Read", "/p/envy.md", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Decide(Request{ToolName: tc.tool, FilePath: tc.path}) != ""
			if got != tc.deny {
				t.Errorf("deny = %v, want %v", got, tc.deny)
			}
		})
	}
}

func TestDecideOnShellCommands(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmd  string
		deny bool
	}{
		{"cat", "cat .env", true},
		{"head", "head -5 .env", true},
		{"grep against the file", "grep TOKEN .env", true},
		{"sed in place", "sed -i s/a/b/ .env", true},
		{"sourcing the secrets file", "source ~/.secrets", true},
		{"dot-sourcing", ". ~/.secrets", true},
		{"a redirect is a read", "while read l; do echo $l; done < .env", true},
		{"laundering through xargs", "export $(cat .env | xargs)", true},
		{"an editor", "code .env", true},
		{"hexdump", "xxd .env", true},
		{"a chained read still counts", "cat .env && warden list", true},
		{"scoped env files too", "cat .env.production", true},

		{"warden itself reads these files; that is the point", "warden list", false},
		{"warden with a file flag", "warden list --file .env.staging", false},
		{"the example file", "cat .env.example", false},
		{"the central schema", "cat ~/.warden/schema", false},
		{"an unrelated grep", "grep -r FOO src/", false},
		{"naming a path is not reading it", `echo "$HOME/.secrets"`, false},
		{"an unrelated command", "ls -la", false},
		{"printenv with no file involved", "printenv", false},
		{"a file merely named like one", "cat envy.md", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Decide(Request{ToolName: "Bash", Command: tc.cmd}) != ""
			if got != tc.deny {
				t.Errorf("deny = %v, want %v for %q", got, tc.deny, tc.cmd)
			}
		})
	}
}

// An unexplained denial produces three more attempts at a workaround. A denial
// that names the replacement produces the replacement.
func TestADenialNamesTheWardenCommandsToUseInstead(t *testing.T) {
	reason := Decide(Request{ToolName: "Bash", Command: "cat .env"})
	if reason == "" {
		t.Fatal("expected a denial")
	}
	for _, want := range []string{"warden has", "warden list", "warden doctor", "warden set --secret"} {
		if !contains(reason, want) {
			t.Errorf("denial should name %q:\n%s", want, reason)
		}
	}
}

// Naming only --secret was not enough, and the gap had a specific shape: an
// agent that had *already* printed a credential was told to have the user type
// it into a prompt, which protects nothing the value has lost. Given advice that
// plainly does not fit, agents wrote the file by hand instead. The denial has to
// carry the whole set and the test for choosing between them, because this text
// is the one an agent is guaranteed to read.
func TestADenialNamesEveryWriteChannelAndHowToChoose(t *testing.T) {
	reason := Decide(Request{ToolName: "Bash", Command: "cat .env"})
	for _, want := range []string{
		"warden set --secret KEY",
		"--from-file",
		"--generate",
		"warden set --exposed KEY",
		// Without the test for choosing, --exposed reads as the convenient one
		// and becomes the way around every refusal.
		"already have it",
		"not a way around a refusal",
	} {
		if !contains(reason, want) {
			t.Errorf("denial should name %q:\n%s", want, reason)
		}
	}
}

// The tool must never describe itself as a security boundary. The pattern list
// is a speed bump list: python -c, a heredoc, a base64 round trip and a dotenv
// loader all walk straight past it. A false claim here is worse than no hook,
// because someone would rely on it.
func TestNothingClaimsThisIsSecurity(t *testing.T) {
	reason := Decide(Request{ToolName: "Bash", Command: "cat .env"})
	for _, banned := range []string{"secure", "security boundary", "prevents", "protects you"} {
		if contains(reason, banned) {
			t.Errorf("denial claims more than it can deliver (%q):\n%s", banned, reason)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 || indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
