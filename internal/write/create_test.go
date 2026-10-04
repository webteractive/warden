package write

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/webteractive/warden/internal/query"
)

func createScope(dir string) query.Scope {
	return query.Scope{Dir: dir, Home: dir}
}

// The file must land at 0600 whatever umask the caller happens to be running
// under, since that is the entire promise of the command.
//
// This pins the outcome, not the mechanism. A umask can only clear permission
// bits, never set them, so requesting 0600 from OpenFile already survives every
// umask — an earlier version of Create chmod'd afterwards "to beat the umask",
// which was dead code resting on a wrong belief. A test written against that
// mechanism would have passed whether the chmod was there or not, and proved
// nothing; this one fails the moment the file stops arriving at 0600.
func TestCreateLandsAt0600UnderAnyUmask(t *testing.T) {
	for _, mask := range []int{0o022, 0o002, 0o000} {
		dir := t.TempDir()
		prev := syscall.Umask(mask)
		res, err := Create(createScope(dir))
		syscall.Umask(prev)
		if err != nil {
			t.Fatalf("umask %04o: %v", mask, err)
		}
		if !res.Created {
			t.Errorf("umask %04o: Created = false", mask)
		}
		st, err := os.Stat(filepath.Join(dir, ".env"))
		if err != nil {
			t.Fatal(err)
		}
		if got := st.Mode().Perm(); got != FileMode {
			t.Errorf("umask %04o: mode = %04o, want %04o", mask, got, FileMode)
		}
	}
}

// Tightening means removing access from other accounts, never handing access
// back to the owner's own tooling. Someone who set 0400 to keep a file
// read-only meant it, and 0400 already satisfies what doctor checks for, so
// there is nothing to fix and nothing to report.
func TestCreateLeavesAStricterModeAlone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte("APP_NAME=Warden\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}

	res, err := Create(createScope(dir))
	if err != nil {
		t.Fatal(err)
	}
	if res.Created || res.Tightened {
		t.Errorf("created/tightened = %v/%v, want false/false", res.Created, res.Tightened)
	}
	if res.Mode != 0o400 {
		t.Errorf("mode = %04o, want 0400 — a stricter mode must survive", res.Mode)
	}
}

// The mode that actually matters: group or other having any access at all is
// what doctor reports, and each of these must be narrowed.
func TestCreateTightensEveryModeDoctorWouldReport(t *testing.T) {
	for _, loose := range []os.FileMode{0o644, 0o604, 0o640, 0o666, 0o777} {
		dir := t.TempDir()
		path := filepath.Join(dir, ".env")
		if err := os.WriteFile(path, []byte("APP_NAME=Warden\n"), loose); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, loose); err != nil {
			t.Fatal(err)
		}

		res, err := Create(createScope(dir))
		if err != nil {
			t.Fatalf("%04o: %v", loose, err)
		}
		if !res.Tightened {
			t.Errorf("%04o: Tightened = false", loose)
		}
		if res.Was != loose {
			t.Errorf("%04o: Was = %04o, want the mode it found", loose, res.Was)
		}
		if res.Mode != FileMode {
			t.Errorf("%04o: mode = %04o, want %04o", loose, res.Mode, FileMode)
		}
	}
}

// Create must never be a way to lose a file. Truncating one would destroy
// credentials that may exist nowhere else, which would make this the most
// dangerous command in the tool rather than the safest.
func TestCreateNeverTouchesExistingContents(t *testing.T) {
	dir := t.TempDir()
	const body = "APP_NAME=Warden\nDB_PASSWORD=hunter2\n"
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	for range 3 {
		if _, err := Create(createScope(dir)); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Errorf("contents changed: %q", got)
	}
}

func TestCreateRefusesADirectoryInTheFilesPlace(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".env"), 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := Create(createScope(dir)); err == nil {
		t.Fatal("want an error when .env is a directory")
	} else if !strings.Contains(err.Error(), "directory") {
		t.Errorf("the error should say what is in the way: %v", err)
	}
}

func TestCreateReportsAMissingProjectDirectory(t *testing.T) {
	if _, err := Create(createScope(filepath.Join(t.TempDir(), "nope"))); err == nil {
		t.Fatal("want an error for a project directory that does not exist")
	}
}

func TestCreateGlobalTargetsTheSecretsFile(t *testing.T) {
	home := t.TempDir()

	res, err := Create(query.Scope{Global: true, Home: home})
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, ".secrets"); res.Path != want {
		t.Errorf("path = %q, want %q", res.Path, want)
	}
	if !res.Created || res.Mode != FileMode {
		t.Errorf("created/mode = %v/%04o", res.Created, res.Mode)
	}
}

// os.Stat and os.Chmod both follow symlinks, so a project whose .env links into
// a shared directory has its target tightened. That is the right file to change
// — but reporting the link while modifying something else would have warden
// name one file and touch another, which is exactly the kind of quiet mismatch
// this tool exists not to have.
func TestCreateReportsTheFileASymlinkActuallyNames(t *testing.T) {
	dir := t.TempDir()
	shared := t.TempDir()
	target := filepath.Join(shared, "app.env")
	if err := os.WriteFile(target, []byte("APP_NAME=Warden\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, ".env")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	res, err := Create(createScope(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Tightened {
		t.Error("the target's loose permissions should have been tightened")
	}
	// EvalSymlinks resolves /var -> /private/var on macOS, so compare the file
	// rather than the string.
	if !sameFile(t, res.Path, target) {
		t.Errorf("Path = %q, want the file the link names (%q)", res.Path, target)
	}
	if got := modePerm(t, target); got != FileMode {
		t.Errorf("target mode = %04o, want %04o", got, FileMode)
	}
}

// A link with nothing on the end of it must say so. Left to O_EXCL this fails
// with a bare "file exists" for a path that visibly has no file, which is the
// least useful thing warden could say.
func TestCreateReportsADanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "gone.env"), filepath.Join(dir, ".env")); err != nil {
		t.Fatal(err)
	}

	_, err := Create(createScope(dir))
	if err == nil {
		t.Fatal("want an error for a dangling symlink")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("the error should name the symlink: %v", err)
	}
}

func modePerm(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

func sameFile(t *testing.T, a, b string) bool {
	t.Helper()
	sa, err := os.Stat(a)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := os.Stat(b)
	if err != nil {
		t.Fatal(err)
	}
	return os.SameFile(sa, sb)
}
