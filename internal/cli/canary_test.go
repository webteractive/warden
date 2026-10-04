package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/webteractive/warden/internal/keyring"
	"github.com/webteractive/warden/internal/prompt"
	"github.com/webteractive/warden/internal/query"
)

// Every value in the fixture is a unique marker. Secret markers must never
// appear in any output stream; public markers legitimately may.
const (
	canaryStripe   = "cnry-stripe-4f81a2c9"
	canaryPassword = "cnry-passwd-77b3e105"
	canaryToken    = "cnry-token-1a9d4f30"
	canaryURL      = "cnry-urlpw-6c2b8e44"
	canaryAppName  = "cnry-appname-public"
	canaryTyped    = "cnry-typed-at-the-prompt"
)

// secretCanaries are the values that must never be printed.
var secretCanaries = []string{canaryStripe, canaryPassword, canaryToken, canaryURL, canaryTyped}

func canaryProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	env := strings.Join([]string{
		"APP_NAME=" + canaryAppName,
		"STRIPE_SECRET=sk_live_" + canaryStripe,
		"DB_PASSWORD=" + canaryPassword,
		"GH_TOKEN=" + canaryToken,
		"APP_URL=https://admin:" + canaryURL + "@example.test",
		"EMPTY_TOKEN=",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	example := "APP_NAME=\nSTRIPE_SECRET=\nDB_PASSWORD=\nNEVER_SET=\n"
	if err := os.WriteFile(filepath.Join(dir, ".env.example"), []byte(example), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// invocations is the coverage table. TestEveryRegisteredCommandIsCoveredByThe
// CanaryTable fails the build if a registered command is absent from it, so a
// new command cannot ship unexercised.
func invocations(dir string) map[string][][]string {
	return map[string][][]string{
		"has": {
			{"has", "STRIPE_SECRET", "--project", dir},
			{"has", "EMPTY_TOKEN", "--project", dir},
			{"has", "ABSENT", "--project", dir},
			{"has", "STRIPE_SECRET", "--project", "/nonexistent"},
		},
		"list": {
			{"list", "--project", dir},
			{"list", "--project", dir, "--json"},
			{"list", "--project", "/nonexistent"},
		},
		"get": {
			{"get", "STRIPE_SECRET", "--project", dir},
			{"get", "DB_PASSWORD", "--project", dir},
			{"get", "APP_URL", "--project", dir},
			{"get", "GH_TOKEN", "--project", dir},
			{"get", "APP_NAME", "--project", dir},
			{"get", "ABSENT", "--project", dir},
		},
		"missing": {
			{"missing", "--project", dir},
			{"missing", "--project", dir, "--json"},
		},
		"classify": {
			{"classify", "STRIPE_SECRET", "--project", dir},
			{"classify", "APP_URL", "--project", dir},
			{"classify", "ABSENT", "--project", dir},
			{"classify", "DB_PASSWORD", "--project", dir, "--json"},
			// --set exercises the write path. The first two are refused on value
			// shape and must not quote the credential they are protecting; the
			// third succeeds, which makes the key readable but must still not
			// print the value as part of confirming that.
			{"classify", "STRIPE_SECRET", "--set", "public", "--project", dir},
			{"classify", "APP_URL", "--set", "public", "--project", dir},
			{"classify", "DB_PASSWORD", "--set", "public", "--project", dir},
			{"classify", "DB_PASSWORD", "--set", "public", "--project", dir, "--json"},
			{"classify", "APP_NAME", "--set", "secret", "--project", dir},
			{"classify", "GH_TOKEN", "--set", "publik", "--project", dir},
		},
		"doctor": {
			{"doctor", "--project", dir},
			{"doctor", "--project", dir, "--json"},
			{"doctor", "--project", dir, "--strict"},
			{"doctor", "--project", dir, "--strict=error"},
			{"doctor", "--project", dir, "--strict=loud"},
		},
		// version opens no file and takes no key. It is in the table because the
		// table is exhaustive by design, not because it is a plausible leak.
		"version": {
			{"version"},
		},
		// init reports a path and a mode and never opens the file, so the only
		// way it could leak is by quoting something it had no reason to read.
		// Both cases run against a fixture whose .env is full of canaries: the
		// first finds the file already there, the second tightens it.
		"init": {
			{"init", "--project", dir},
			{"init", "--project", dir, "--json"},
		},
		"set": {
			{"set", "DB_PASSWORD", canaryPassword, "--project", dir},
			{"set", "APP_NAME", "renamed", "--project", dir},
			{"set", "MODE", "sk_live_" + canaryStripe, "--project", dir},
			{"set", "--secret", "DB_PASSWORD", "--project", dir},
			{"set", "--secret", "DB_PASSWORD", canaryPassword, "--project", dir},
		},
		"unset": {
			{"unset", "DB_PASSWORD", "--project", dir},
			{"unset", "GH_TOKEN", "--project", dir},
			{"unset", "EMPTY_TOKEN", "--project", dir},
			{"unset", "ABSENT", "--project", dir},
			{"unset", "APP_NAME", "--project", "/nonexistent"},
		},
		"clear": {
			{"clear", "STRIPE_SECRET", "--project", dir},
			{"clear", "EMPTY_TOKEN", "--project", dir},
			{"clear", "ABSENT", "--project", dir},
		},
		"refs": {
			{"refs", "--project", dir},
			{"refs", "--project", dir, "--json"},
			{"refs", "--project", dir, "--strict"},
			{"refs", "--project", dir, "--undeclared"},
			{"refs", "--project", dir, "--unused"},
			{"refs", "--project", dir, "--pattern", "bad(("},
		},
		"hook": {
			{"hook"},
			{"hook", "--check", "--settings", "/nonexistent/settings.json"},
			{"hook", "--guard"},
			{"hook", "--target", "emacs"},
			{"hook", "--check", "--settings", "/nonexistent/settings.json"},
			{"hook", "--install", "--settings", "/nonexistent/settings.json"},
		},
		"vault init": {
			{"vault", "init"},
			{"vault", "init"}, // second call is refused: a vault already exists
			{"vault", "init", "--global"},
		},
		"vault set": {
			{"vault", "set", "CANARY_TOKEN"},
			{"vault", "set", "stripe/live", "--key", "STRIPE_SECRET"},
			{"vault", "set", "stripe/live", "--key", "STRIPE_SECRET"}, // replace path
			{"vault", "set", "no/key/given"},
			{"vault", "set", "CANARY_TOKEN", "--ttl", "8h"},
			{"vault", "set", "CANARY_TOKEN", "--ttl", "31d"},
			{"vault", "set", "bad name"},
		},
		"vault list": {
			{"vault", "list"},
			{"vault", "list", "--json"},
		},
		"vault has": {
			{"vault", "has", "CANARY_TOKEN"},
			{"vault", "has", "absent"},
		},
		"vault edit": {
			{"vault", "edit", "CANARY_TOKEN", "--key", "OTHER_TOKEN"},
			{"vault", "edit", "CANARY_TOKEN", "--ttl", "none"},
			{"vault", "edit", "absent", "--key", "X"},
			{"vault", "edit", "CANARY_TOKEN"},
		},
		"vault rm": {
			{"vault", "rm", "CANARY_TOKEN"},
			{"vault", "rm", "absent"},
		},
		"vault push": {
			{"vault", "push", "stripe/live", "--to", "", "--yes"},
			{"vault", "push", "stripe/live", "--to", "", "--yes"}, // now already set
			{"vault", "push", "stripe/live", "--to", "", "--yes", "--force"},
			{"vault", "push", "stripe/live", "--to", "", "--as", "OTHER_KEY", "--yes"},
			{"vault", "push", "absent", "--to", "", "--yes"},
		},
		"mcp": nil, // long-running stdio server; covered by internal/mcpserver tests
	}
}

func TestNoCommandLeaksASecretValue(t *testing.T) {
	// The prompt returns a canary, so the confirmation path is exercised with a
	// value that must not be echoed back.
	prev := SetPrompter
	SetPrompter = prompt.Fake{Value: canaryTyped}
	t.Cleanup(func() { SetPrompter = prev })

	// The vault lives under $HOME, and no test may touch the developer's real
	// one. Redirect it and install a fake keyring for the whole suite.
	t.Setenv("HOME", t.TempDir())
	query.VaultKeyring = &keyring.Fake{}
	t.Cleanup(func() { query.VaultKeyring = nil })

	for name, argsets := range invocations("") {
		for _, args := range argsets {
			t.Run(name+"/"+strings.Join(args, "_"), func(t *testing.T) {
				// Fresh fixture per invocation: writes must not bleed across cases.
				dir := canaryProject(t)
				args = append([]string(nil), args...)
				for i, a := range args {
					if (a == "--project" || a == "--to") && i+1 < len(args) && args[i+1] == "" {
						args[i+1] = dir
					}
				}

				var out, errw bytes.Buffer
				_ = Run(args, &out, &errw)
				combined := out.String() + errw.String()

				for _, c := range secretCanaries {
					if strings.Contains(combined, c) {
						t.Fatalf("LEAK: %v printed the secret marker %s\n--- output ---\n%s",
							args, c, combined)
					}
				}
			})
		}
	}
}

// Global-scope invocations get their own fixture rather than a table entry,
// because they need $HOME redirected. Running them against the real $HOME would
// have the test suite read the user's actual ~/.secrets — never acceptable.
func TestGlobalScopeCommandsDoNotLeak(t *testing.T) {
	home := t.TempDir()
	body := "export GH_TOKEN=" + canaryToken + "\nexport STRIPE_SECRET=sk_live_" + canaryStripe + "\n"
	if err := os.WriteFile(filepath.Join(home, ".secrets"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	// Without this, the write commands here reach prompt.Default() — which on a
	// developer's Mac is a real osascript dialog, and the suite sits waiting on a
	// 60-second timeout for a prompt nobody is looking at.
	prev := SetPrompter
	SetPrompter = prompt.Fake{Value: canaryTyped}
	t.Cleanup(func() { SetPrompter = prev })

	for _, args := range [][]string{
		{"has", "GH_TOKEN", "--global"},
		{"list", "--global"},
		{"list", "--global", "--json"},
		{"get", "GH_TOKEN", "--global"},
		{"classify", "GH_TOKEN", "--global"},
		{"doctor", "--global"},
		{"missing", "--global"},
		{"set", "GH_TOKEN", canaryToken, "--global"},
		{"classify", "GH_TOKEN", "--set", "public", "--global"},
		{"unset", "GH_TOKEN", "--global"},
		{"clear", "STRIPE_SECRET", "--global"},
		{"refs", "--global"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var out, errw bytes.Buffer
			_ = Run(args, &out, &errw)
			combined := out.String() + errw.String()
			for _, c := range secretCanaries {
				if strings.Contains(combined, c) {
					t.Fatalf("LEAK: %v printed the secret marker %s\n--- output ---\n%s",
						args, c, combined)
				}
			}
		})
	}
}

func TestEveryRegisteredCommandIsCoveredByTheCanaryTable(t *testing.T) {
	covered := invocations("")
	root := newRootCmd(&bytes.Buffer{}, &bytes.Buffer{})
	for _, name := range commandNames(root) {
		if _, ok := covered[name]; !ok {
			t.Errorf("command %q has no entry in the canary table — add one before shipping it. "+
				"If it genuinely cannot be exercised here, map it to nil with a comment saying why.",
				name)
		}
	}
}
