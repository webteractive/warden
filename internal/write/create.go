package write

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/webteractive/warden/internal/query"
)

// FileMode is the permission every file warden creates gets: readable and
// writable by its owner, and by nobody else. It is the mode doctor checks for,
// so the two agree by construction.
const FileMode os.FileMode = 0o600

// CreateResult reports what Create actually did, so a caller can say so rather
// than printing the outcome it assumed. The three cases are genuinely different
// news: a new file, someone else's loose file tightened, or nothing to do.
type CreateResult struct {
	Path string
	// Created is set when the file did not exist and now does.
	Created bool
	// Tightened is set when the file already existed with permissions that let
	// somebody other than its owner read it, and those were narrowed.
	Tightened bool
	// Was is the mode found on an existing file, and 0 when one was created.
	Was os.FileMode
	// Mode is the mode the file has now.
	Mode os.FileMode
}

// Create makes the scope's configuration file if it is missing, and tightens its
// permissions if they are loose. It never reads or changes an existing file's
// contents.
//
// Whatever creates an env file first decides who can read it, and the usual
// candidates do not think about that at all: an editor, `cp .env.example .env`,
// a framework installer. All of them apply the umask, which on a default macOS
// or Linux account leaves a file of credentials readable by every other account
// on the machine. That is the finding doctor reports most often, and by the time
// it reports it the secrets have already been written into a world-readable
// file. Creating the file through warden is how it starts at FileMode instead.
//
// Creating is deliberately not the same as adopting. The project directory is
// used exactly as given, without the upward walk OpenDotenv does: running this
// inside a subdirectory of a project that already has an .env above it means
// "make one here", and quietly tightening the parent's instead — or reporting
// the parent's path as though it were this directory's — would be a surprise in
// the one command whose entire job is to be unsurprising about permissions.
//
// Safe to re-run, which is what makes it usable from a setup script.
func Create(sc query.Scope) (CreateResult, error) {
	path, err := createPath(sc)
	if err != nil {
		return CreateResult{}, err
	}
	path, err = resolveLink(path)
	if err != nil {
		return CreateResult{}, err
	}

	st, err := os.Stat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return CreateResult{}, err
	}
	if err == nil {
		return tightenExisting(path, st)
	}

	// O_EXCL so a file that appears between the stat above and here is never
	// truncated. Losing somebody's credentials to a race in the command that
	// exists to protect them would be the worst possible trade.
	//
	// FileMode needs no Chmod after it. OpenFile's mode is masked by the umask,
	// but a umask only ever clears bits, and 0600 has no group or other bits to
	// clear — so every umask yields exactly 0600. (An earlier version of this
	// function chmod'd afterwards "to beat the umask", which sounds right and is
	// not: the umask cannot loosen a mode, only tighten one.)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, FileMode)
	if err != nil {
		return CreateResult{}, err
	}
	if err := f.Close(); err != nil {
		return CreateResult{}, err
	}
	return CreateResult{Path: path, Created: true, Mode: FileMode}, nil
}

// tightenExisting is the branch Create takes when the file is already there:
// report it unchanged when only its owner can read it, and narrow it when
// anybody else can.
func tightenExisting(path string, st os.FileInfo) (CreateResult, error) {
	if st.IsDir() {
		return CreateResult{}, fmt.Errorf("%s is a directory, not a file warden can write", path)
	}
	found := st.Mode().Perm()
	res := CreateResult{Path: path, Was: found, Mode: found}
	if found&0o077 == 0 {
		return res, nil
	}
	if err := os.Chmod(path, FileMode); err != nil {
		return CreateResult{}, err
	}
	res.Tightened, res.Mode = true, FileMode
	return res, nil
}

// resolveLink follows a symlink at path and returns the file it actually names.
//
// os.Stat and os.Chmod both follow symlinks, so without this a project whose
// .env is a link into a shared directory gets its *target* tightened while the
// result reports the link — warden would name one file on screen and modify a
// different one. For a tool whose whole value is being trustworthy about where
// secrets live, misnaming the file it just changed is the worst kind of bug it
// can have: quiet, plausible, and about permissions.
//
// Following rather than refusing is right because warden already follows
// elsewhere — envfile.Save renames a temp file over the path, which replaces a
// link with a regular file the first time anything is written. A link pointing
// at a real env file is a legitimate layout, and 0600 is the correct mode for
// whatever file it names.
//
// A missing path is not an error here: that is the ordinary case where Create
// goes on to make the file.
func resolveLink(path string) (string, error) {
	st, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return path, nil
		}
		return "", err
	}
	if st.Mode()&os.ModeSymlink == 0 {
		return path, nil
	}
	// A dangling link is reported here rather than left to O_EXCL, which fails
	// with a bare "file exists" for a path that visibly has no file.
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("%s is a symlink warden cannot follow: %w", path, err)
	}
	return target, nil
}

// createPath resolves which file this scope's Create acts on.
func createPath(sc query.Scope) (string, error) {
	if sc.Global {
		if sc.Home == "" {
			return "", errors.New("cannot locate the home directory")
		}
		return filepath.Join(sc.Home, ".secrets"), nil
	}
	dir, err := filepath.Abs(sc.Dir)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(dir)
	if err != nil {
		return "", fmt.Errorf("%s: %w", dir, err)
	}
	if !st.IsDir() {
		return "", fmt.Errorf("%s is not a directory", dir)
	}
	return filepath.Join(dir, ".env"), nil
}
