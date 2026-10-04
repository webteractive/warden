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
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// Request is one tool call, reduced to the fields that matter.
type Request struct {
	ToolName string
	FilePath string
	Command  string
	// Glob is Grep's file filter. A glob that selects an env file reads it as
	// surely as a path naming one.
	Glob string
}

// Target names which kind of file a denial was about, so a caller that words
// its own message does not have to match this package's text.
type Target string

const (
	TargetEnv     Target = "env"
	TargetSecrets Target = "secrets"
)

// Decision is a denial's text and the file it was about. The zero value allows
// the call.
type Decision struct {
	Reason string
	Target Target
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

// editNote follows a denied edit. There is no override for editing an env file
// directly: the harness's Edit and Write refuse a file that has not been read,
// so allowing an edit would allow the read. Saying where changes go instead is
// what stops the next attempt being a hand-rolled sed.
const editNote = `Env files are not edited directly — warden makes every change:
  warden set ...            add or change a key, through a channel above
  warden unset KEY          remove a key
  warden clear KEY          empty a key, keeping it declared
  warden init               create the file, readable only by you (0600)`

// secretsNote follows any denial that touches .secrets, which unlike .env has
// no circumstance under which reading it is permitted.
const secretsNote = `~/.secrets is never readable, under any request. Add --global to the commands above.`

// editTools change a file, as opposed to only reading it.
var editTools = map[string]bool{"Edit": true, "Write": true, "NotebookEdit": true}

// shellTools run a shell command whose output reaches the model. A Monitor's
// command streams it line by line, which is the same read.
var shellTools = map[string]bool{"Bash": true, "Monitor": true}

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
// envy.md and .environment out; group 2 is the name itself. A backtick counts
// as a boundary on either side, so `cat .env` in backticks still names the
// file; it is spelled \x60 because a raw string cannot hold one.
var envFileRe = regexp.MustCompile(`(^|[/\s"'=(\x60])` + envFileNames + `($|[\s"'):;&|\x60])`)

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
	return Detail(r).Reason
}

// Detail decides a call and says which file a denial was about.
func Detail(r Request) Decision {
	switch {
	case readTools[r.ToolName]:
		if IsProtected(r.FilePath) {
			return deny("reading "+filepath.Base(r.FilePath)+" directly", r.ToolName, targetOf(r.FilePath))
		}
	case r.ToolName == "Grep":
		if IsProtected(r.FilePath) {
			return deny("searching "+filepath.Base(r.FilePath)+" directly", r.ToolName, targetOf(r.FilePath))
		}
		if t := globTarget(r.Glob); t != "" {
			return deny("searching an env file through a glob", r.ToolName, t)
		}
	case shellTools[r.ToolName]:
		// Judge each segment on its own, so a chained read is not laundered by a
		// harmless command sitting next to it. Every segment is judged, so a
		// command naming both files is reported against the stricter one.
		var target Target
		for _, seg := range splitSegments(r.Command) {
			target = stricter(target, deniedSegment(seg))
		}
		if target != "" {
			return deny("reading an env file directly", r.ToolName, target)
		}
	}
	return Decision{}
}

// deny assembles a denial: what was refused, the replacements, and the notes
// that only some denials need.
func deny(what, tool string, target Target) Decision {
	reason := "Denied: " + what + ".\n\n" + guidance
	if editTools[tool] {
		reason += "\n\n" + editNote
	}
	if target == TargetSecrets {
		reason += "\n\n" + secretsNote
	}
	return Decision{Reason: reason, Target: target}
}

// targetOf names the target for a file the guard protects.
func targetOf(name string) Target {
	if filepath.Base(strings.TrimSpace(name)) == ".secrets" {
		return TargetSecrets
	}
	return TargetEnv
}

// stricter returns whichever target carries more weight; "" is no target.
func stricter(a, b Target) Target {
	if a == TargetSecrets || b == TargetSecrets {
		return TargetSecrets
	}
	if a != "" {
		return a
	}
	return b
}

// globCandidates are names a glob is tried against. A glob that names one of
// them, or that is itself shaped like a protected name, selects a protected file.
var globCandidates = []string{".env", ".env.local", ".env.production", ".secrets"}

// globTarget reports the target a Grep glob selects, or "". A glob must name an
// env file to select one: `*` and `*.*` match .env as surely as `.env` does, but
// they are how every search over a tree is written, and denying them would deny
// Grep outright. ripgrep skips hidden files under them by default anyway.
func globTarget(glob string) Target {
	if !strings.Contains(glob, "env") && !strings.Contains(glob, "secrets") {
		return ""
	}
	var target Target
	for _, alt := range expandBraces(glob) {
		base := path.Base(alt)
		if IsProtected(base) {
			target = stricter(target, targetOf(base))
			continue
		}
		for _, name := range globCandidates {
			if ok, _ := path.Match(base, name); ok {
				target = stricter(target, targetOf(name))
			}
		}
	}
	return target
}

// expandBraces expands `{a,b}` alternatives, which path.Match does not know.
func expandBraces(glob string) []string {
	open := strings.Index(glob, "{")
	if open < 0 {
		return []string{glob}
	}
	end := strings.Index(glob[open:], "}")
	if end < 0 {
		return []string{glob}
	}
	end += open
	var out []string
	for _, alt := range strings.Split(glob[open+1:end], ",") {
		out = append(out, expandBraces(glob[:open]+alt+glob[end+1:])...)
	}
	return out
}

// segmentRe matches the operators that join separate commands. Compiled once at
// package level like the other two patterns here — this one sits on the hook's
// hot path, which runs on every Bash call the harness makes.
var segmentRe = regexp.MustCompile(`&&|\|\||;|\||\n`)

// splitSegments breaks a command on the operators that join separate commands.
func splitSegments(cmd string) []string {
	return segmentRe.Split(cmd, -1)
}

// deniedSegment returns the target a segment reads, or "" when it reads none.
func deniedSegment(seg string) Target {
	fields := strings.Fields(seg)
	if len(fields) == 0 {
		return ""
	}
	// warden reads these files; that is the point of it.
	if runsOnlyWarden(fields[0], seg) {
		return ""
	}
	// Nothing protected is named, so nothing here can be a read of one. Asking
	// first makes the redirect check below a plain one and saves a second scan
	// of the segment in the common case.
	target := mentionsProtected(seg)
	if target == "" {
		return ""
	}
	// `... < .env` is the read itself, with no reader command in the segment.
	if redirectRe.MatchString(seg) {
		return target
	}
	for _, f := range fields {
		if readers[commandToken(f)] {
			return target
		}
	}
	return ""
}

// runsOnlyWarden reports whether a segment runs warden and nothing else. The
// exemption is for warden reading a file without printing it; it does not cover
// a substitution or redirect riding in the same segment, which runs first and
// whose output cobra echoes back in an unknown-argument error. warden is taken
// by name or by an absolute path — a relative ./x/warden is whatever binary
// happens to be called that.
func runsOnlyWarden(bin, seg string) bool {
	if filepath.Base(bin) != "warden" {
		return false
	}
	if bin != "warden" && !strings.HasPrefix(bin, "/") && !strings.HasPrefix(bin, "~/") {
		return false
	}
	return !strings.ContainsAny(seg, "`<>") && !strings.Contains(seg, "$(")
}

// commandToken reduces a shell word to the command it invokes. A reader hidden
// inside a substitution — export $(cat .env | xargs), diff <(cat .env) x — is
// still a reader, and the substitution is exactly how someone routes around a
// naive matcher.
func commandToken(f string) string {
	f = strings.TrimLeft(f, "$(`\"'\\{<>")
	return filepath.Base(f)
}

// mentionsProtected returns the strictest target among the env files the
// segment names that are not one of the readable ones, or "" for none.
func mentionsProtected(seg string) Target {
	var target Target
	for _, m := range envFileRe.FindAllStringSubmatch(seg, -1) {
		if !readableNames[m[2]] {
			target = stricter(target, targetOf(m[2]))
		}
	}
	return target
}
