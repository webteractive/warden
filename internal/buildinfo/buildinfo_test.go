package buildinfo

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The injection path is a string in two config files and a variable name in this
// one, with nothing but spelling holding them together. Get it wrong and the
// linker does not complain — `-X` on an unknown symbol is silently ignored — so
// the failure is a released binary that reports its version as "dev", which is
// the one answer worse than no answer at all.
//
// This is the check that the two halves still agree.
func TestTheBuildInjectsIntoThisPackage(t *testing.T) {
	pkg := modulePath(t) + "/internal/buildinfo"

	for _, f := range []struct {
		path string
		want []string
	}{
		// goreleaser cuts the real releases, so it must set all three.
		{"../../.goreleaser.yaml", []string{pkg + ".version=", pkg + ".commit=", pkg + ".date="}},
		// install.sh --source builds from a checkout, where the toolchain already
		// stamps the commit and time into the binary; only the version needs
		// injecting, because git describe knows the tag and the compiler does not.
		{"../../install.sh", []string{pkg + ".version="}},
	} {
		body := read(t, f.path)
		for _, want := range f.want {
			if !strings.Contains(body, want) {
				t.Errorf("%s does not inject %q — a released binary would report \"dev\"",
					filepath.Base(f.path), want)
			}
		}
	}
}

// Every name the configs above inject into has to exist here, and the compiler
// is what proves it: these are the package's own variables, so a rename breaks
// this file rather than silently breaking the release.
func TestTheInjectedVariablesExist(t *testing.T) {
	for name, v := range map[string]*string{"version": &version, "commit": &commit, "date": &date} {
		if v == nil {
			t.Errorf("%s is not a settable string", name)
		}
	}
}

// Nothing injected, and no module version to fall back on: the answer has to be
// a word, never an empty string. A version line that prints nothing looks like a
// crash to whatever is parsing it.
func TestVersionAlwaysAnswers(t *testing.T) {
	restore := swap(t, "", "", "")
	defer restore()

	if got := Version(); got == "" {
		t.Error("Version() is empty; it must always name something")
	}
	if got := String(); got == "" {
		t.Error("String() is empty")
	}
}

func TestStringRendersVersionCommitAndDate(t *testing.T) {
	restore := swap(t, "0.1.6", "ca8363f46d32180d9e1149e8e5f9d84347da7d5d", "2026-09-05T00:04:11Z")
	defer restore()

	// The commit is abbreviated and the clock time dropped: both are noise at
	// full length, and "which build" is a question a human reads the answer to.
	const want = "0.1.6 (ca8363f, 2026-09-05)"
	if got := String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// A tagged build with no commit stamped must still render cleanly — no empty
// parentheses, no trailing comma.
func TestStringOmitsWhatItDoesNotKnow(t *testing.T) {
	restore := swap(t, "0.1.6", "", "")
	defer restore()

	if got := String(); regexp.MustCompile(`\(\s*\)|,\s*\)`).MatchString(got) {
		t.Errorf("String() = %q has an empty or dangling detail group", got)
	}
}

func swap(t *testing.T, v, c, d string) func() {
	t.Helper()
	pv, pc, pd := version, commit, date
	version, commit, date = v, c, d
	return func() { version, commit, date = pv, pc, pd }
}

func modulePath(t *testing.T) string {
	t.Helper()
	for _, line := range strings.Split(read(t, "../../go.mod"), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.TrimSpace(rest)
		}
	}
	t.Fatal("no module line in go.mod")
	return ""
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// goreleaser injects "0.1.6" and install.sh injects `git describe`, which says
// "v0.1.6". Two builds of one commit must not report the number differently.
func TestVersionReportsTheSameShapeWhicheverBuildInjectedIt(t *testing.T) {
	for _, injected := range []string{"0.1.6", "v0.1.6"} {
		restore := swap(t, injected, "", "")
		got := Version()
		restore()
		if got != "0.1.6" {
			t.Errorf("injected %q -> Version() = %q, want %q", injected, got, "0.1.6")
		}
	}
}
