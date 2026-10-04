// Package hook decides whether a harness tool call is trying to read an env
// file, and produces the settings a harness needs to ask.
//
// What this is: a speed bump list that closes the accidental path and teaches
// the replacement at the moment of need. What it is not: containment. A command
// can read a file in ways no matcher enumerates — python -c, a heredoc, a base64
// round trip, a build script that loads dotenv. Nothing here may describe itself
// as security, and a test enforces that.
package hook

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Request is one tool call, reduced to the two fields that matter.
type Request struct {
	ToolName string
	FilePath string
	Command  string
}

// guidance is the denial message. It is the actual feature: an unexplained
// denial produces three more attempts at a workaround.
const guidance = `Use warden, which answers this without exposing values:
  warden has KEY            is it set?              (exit 0/1)
  warden list               keys, class, set/unset
  warden missing            declared but not set
  warden doctor             what is wrong here
  warden refs               keys the code reads and the file does not set
  warden get KEY            public keys only

To write a key, pick by where the value already is:
  you do not have it        warden set --secret KEY
                            the user types it into a prompt you never see
  it is in a file           warden set --secret KEY --from-file PATH
                            warden opens the file; do not cat it first
  it needs to be new        warden set --secret KEY --generate
                            warden mints it; nobody learns it, including you
  you already have it       warden set --exposed KEY VALUE
                            it was printed by a tool, pasted by the user, or is
                            in scrollback; this records that it is burned
  it is not sensitive       warden set KEY VALUE

--exposed is only for a value that is already out. If you do not have the
value, use --secret — --exposed is not a way around a refusal. Never run it
on a value you got by reading .env or ~/.secrets.
Add --global for ~/.secrets, --project DIR to pick the project.`

// readTools open a file by path.
var readTools = map[string]bool{
	"Read": true, "Edit": true, "Write": true, "NotebookEdit": true,
}

// readableNames are the env-adjacent files that exist to be read. Blocking them
// is the fastest way to have the whole hook removed in irritation.
var readableNames = map[string]bool{
	".env.example": true, ".env.schema": true, ".env.sample": true, ".env.dist": true,
}

// readers are commands whose job is to emit a file's contents.
var readers = map[string]bool{
	"cat": true, "head": true, "tail": true, "less": true, "more": true, "bat": true,
	"grep": true, "rg": true, "ag": true, "ack": true, "sed": true, "awk": true,
	"strings": true, "xxd": true, "od": true, "hexdump": true, "nl": true, "cut": true,
	"open": true, "code": true, "vim": true, "vi": true, "nano": true, "emacs": true,
	"source": true, ".": true, "cp": true, "mv": true, "dd": true, "tee": true,
}

// envFileNames is what an env file's name looks like, defined once so the two
// patterns below cannot drift apart.
const envFileNames = `(\.env(\.[A-Za-z0-9_-]+)?|\.secrets)`

// envFileRe matches a path that names an env file. The surrounding guards keep
// envy.md and .environment out; group 2 is the name itself.
var envFileRe = regexp.MustCompile(`(^|[/\s"'=(])` + envFileNames + `($|[\s"'):;&|])`)

// redirectRe catches `... < .env`, where the redirect is the read and no reader
// command appears anywhere in the segment.
var redirectRe = regexp.MustCompile(`<\s*[^\s<>|&]*` + envFileNames + `\b`)

// IsProtected reports whether path names a file warden exists to keep closed.
func IsProtected(path string) bool {
	name := filepath.Base(strings.TrimSpace(path))
	if readableNames[name] {
		return false
	}
	return name == ".env" || name == ".secrets" || strings.HasPrefix(name, ".env.")
}

// Decide returns the reason a call must be denied, or "" to allow it.
func Decide(r Request) string {
	if readTools[r.ToolName] {
		if IsProtected(r.FilePath) {
			return "Denied: reading " + filepath.Base(r.FilePath) + " directly.\n\n" + guidance
		}
		return ""
	}
	if r.ToolName != "Bash" {
		return ""
	}
	// Judge each segment on its own, so a chained read is not laundered by a
	// harmless command sitting next to it.
	for _, seg := range splitSegments(r.Command) {
		if deniedSegment(seg) {
			return "Denied: reading an env file directly.\n\n" + guidance
		}
	}
	return ""
}

// segmentRe matches the operators that join separate commands. Compiled once at
// package level like the other two patterns here — this one sits on the hook's
// hot path, which runs on every Bash call the harness makes.
var segmentRe = regexp.MustCompile(`&&|\|\||;|\||\n`)

// splitSegments breaks a command on the operators that join separate commands.
func splitSegments(cmd string) []string {
	return segmentRe.Split(cmd, -1)
}

func deniedSegment(seg string) bool {
	fields := strings.Fields(seg)
	if len(fields) == 0 {
		return false
	}
	// warden reads these files; that is the point of it.
	if filepath.Base(fields[0]) == "warden" {
		return false
	}
	// Nothing protected is named, so nothing here can be a read of one. Asking
	// first makes the redirect check below a plain one and saves a second scan
	// of the segment in the common case.
	if !mentionsProtected(seg) {
		return false
	}
	// `... < .env` is the read itself, with no reader command in the segment.
	if redirectRe.MatchString(seg) {
		return true
	}
	for _, f := range fields {
		if readers[commandToken(f)] {
			return true
		}
	}
	return false
}

// commandToken reduces a shell word to the command it invokes. A reader hidden
// inside a substitution — export $(cat .env | xargs) — is still a reader, and
// the substitution is exactly how someone routes around a naive matcher.
func commandToken(f string) string {
	f = strings.TrimLeft(f, "$(`\"'\\{")
	return filepath.Base(f)
}

// mentionsProtected reports whether the segment names an env file that is not
// one of the readable ones.
func mentionsProtected(seg string) bool {
	for _, m := range envFileRe.FindAllStringSubmatch(seg, -1) {
		if !readableNames[m[2]] {
			return true
		}
	}
	return false
}
