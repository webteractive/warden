package cli

import (
	"os/exec"
	"strings"
	"testing"
)

// The safety property depends on internal/query being the only way out of
// internal/store, and internal/write the only way in. The vault adds two more
// packages a surface must not reach: internal/vault holds values, and
// internal/keyring holds the key that unseals them. A surface needs neither.
//
// This checks .Imports rather than .TestImports deliberately — a test file may
// import keyring to install a fake, which is how the vault is exercised without
// touching a real keychain.
func TestSurfacePackagesDoNotImportTheValueLayersDirectly(t *testing.T) {
	forbidden := []string{
		"github.com/webteractive/warden/internal/store",
		"github.com/webteractive/warden/internal/vault",
		"github.com/webteractive/warden/internal/keyring",
	}

	for _, pkg := range []string{
		"github.com/webteractive/warden/internal/cli",
		"github.com/webteractive/warden/internal/mcpserver",
		"github.com/webteractive/warden/cmd/warden",
	} {
		out, err := exec.Command("go", "list", "-f", "{{join .Imports \"\\n\"}}", pkg).Output()
		if err != nil {
			t.Fatalf("go list %s: %v", pkg, err)
		}
		for _, imp := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			for _, bad := range forbidden {
				if imp == bad {
					t.Errorf("%s imports %s directly — it must go through internal/query or internal/write",
						pkg, bad)
				}
			}
		}
	}
}

// Expose is the single documented escape hatch. Keeping its call sites few and
// deliberate is what makes them reviewable; this test surfaces new ones.
func TestExposeCallSitesStayFew(t *testing.T) {
	out, err := exec.Command("grep", "-rn", "--include=*.go", ".Expose()", "../..").Output()
	if err != nil && len(out) == 0 {
		t.Skip("grep unavailable")
	}
	var production []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" || strings.Contains(line, "_test.go") {
			continue
		}
		production = append(production, line)
	}
	// classify (shape check), query.Get, write.SetPublic/SetSecret,
	// vault sealDoc (the wire type that defeats Secret redaction),
	// vault deriveFromPassphrase, vault decodeMasterKey,
	// keyring Security.Set and SecretTool.Set (stdin, never argv),
	// write.setFromVault (the value crossing on vault push),
	// dialog.Main (the dialog child handing the value up its pipe to warden).
	//
	// This counts matching *lines*, not calls: Security.Set exposes twice on one
	// line because security asks for the value and then a retype.
	const budget = 11
	if len(production) > budget {
		t.Errorf("Expose() is called in %d production sites, budget is %d.\n"+
			"Each one lets a value escape the safe zone — review these and raise the budget "+
			"deliberately if the new call site is justified:\n%s",
			len(production), budget, strings.Join(production, "\n"))
	}
}

// internal/refs deals in key names and file paths. Keeping it structurally
// unable to hold a value is what makes it the cheapest analysis here to trust:
// the worst a bug in it can do is name the wrong file.
func TestRefsPackageCannotReachAValue(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", "{{join .Deps \"\\n\"}}",
		"github.com/webteractive/warden/internal/refs").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, dep := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		switch dep {
		case "github.com/webteractive/warden/internal/store",
			"github.com/webteractive/warden/internal/secret",
			"github.com/webteractive/warden/internal/query":
			t.Errorf("internal/refs depends on %s — it must never be able to hold a value", dep)
		}
	}
}

// TestMCPCannotReachTheEscalatingWritePaths pins a security property that
// nothing else enforces.
//
// SetExposed accepts a value on the caller's terms rather than through a channel
// warden controls, and Loosen records a key as public without the retype
// ceremony. Both are safe when a human types the flag and neither is safe as a
// tool call, so the MCP surface must not reach them — the same rule that keeps
// `classify --set` off the MCP surface.
//
// The SetPublic assertion is a positive control: it proves this test can see a
// call at all, so a passing run means the absences are real rather than a broken
// grep quietly reporting nothing.
func TestMCPCannotReachTheEscalatingWritePaths(t *testing.T) {
	out, err := exec.Command("grep", "-rn", "--include=*.go", "-e", "SetPublic",
		"-e", "SetExposed", "-e", "Loosen", "../mcpserver").Output()
	if err != nil && len(out) == 0 {
		t.Skip("grep unavailable")
	}
	var production string
	for _, line := range strings.Split(string(out), "\n") {
		if line != "" && !strings.Contains(line, "_test.go") {
			production += line + "\n"
		}
	}

	if !strings.Contains(production, "SetPublic") {
		t.Fatal("positive control failed: this test cannot detect a write call, " +
			"so its other assertions prove nothing")
	}
	for _, forbidden := range []string{"SetExposed", "Loosen"} {
		if strings.Contains(production, forbidden) {
			t.Errorf("mcpserver reaches %s — that path is for a human at a terminal, "+
				"not for a tool call:\n%s", forbidden, production)
		}
	}
}
