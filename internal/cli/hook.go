package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/webteractive/warden/internal/hook"
)

// GuardInput is where --guard reads the tool call from. Tests replace it;
// nothing else should.
var GuardInput io.Reader = os.Stdin

// guardPayload is the part of a PreToolUse payload the guard needs. Everything
// else in it is ignored, so a harness adding fields cannot break this.
type guardPayload struct {
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command      string `json:"command"`
		FilePath     string `json:"file_path"`
		NotebookPath string `json:"notebook_path"`
		LSPPath      string `json:"filePath"`
		Path         string `json:"path"`
		Glob         string `json:"glob"`
	} `json:"tool_input"`
}

// guardAnswer is --guard's --json output: the decision, and on a denial the
// file it was about and the text to show. The exit code is unchanged by --json.
type guardAnswer struct {
	Decision string `json:"decision"`
	Target   string `json:"target,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// guardCommand is what the installed hook runs.
const guardCommand = "warden hook --guard"

// GuardProbe reports whether the warden on PATH can actually run the guard, and
// LookWarden finds it. Both are variables because --check otherwise reports on
// whatever binary happens to be installed on the machine running the tests —
// which on CI is none, and on a developer's Mac is the previous release.
var (
	GuardProbe = probeGuard
	LookWarden = func() (string, error) { return exec.LookPath("warden") }
)

// probeGuard runs the installed binary's guard against an empty payload. A
// warden predating `hook` fails here, which matters more than it looks: the
// guard fails open, so an older binary means every read is allowed while the
// user believes the hook is working.
func probeGuard(bin string) error {
	cmd := exec.Command(bin, "hook", "--guard")
	cmd.Stdin = strings.NewReader("{}")
	return cmd.Run()
}

func addHookCommand(root *cobra.Command, out io.Writer) {
	cmd := &cobra.Command{
		Use:   "hook",
		Short: "print or install the harness hook that redirects env reads to warden",
		Long: "Print, install or check the PreToolUse hook that denies direct reads of\n" +
			".env and ~/.secrets and names the warden command to use instead.\n\n" +
			"Printing is the default: nothing is written until you pass --install --yes.\n\n" +
			"What this is: a speed bump list. It closes the path taken by accident and\n" +
			"teaches the replacement at the moment of need. What it is not: containment.\n" +
			"A command can read a file in ways no matcher enumerates — python -c, a\n" +
			"script written by a heredoc and run later, a base64 round trip, a build\n" +
			"script that loads dotenv. Warden is not a boundary and this hook does not\n" +
			"make it one.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if guard, _ := cmd.Flags().GetBool("guard"); guard {
				return runGuard(out, jsonFlag(cmd))
			}
			if target, _ := cmd.Flags().GetString("target"); target != "claude" {
				return &ExitError{Code: CodeError, Msg: fmt.Sprintf(
					"warden: unsupported --target %q — only claude is supported today", target)}
			}

			path, err := settingsPath(cmd)
			if err != nil {
				return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
			}
			yes, _ := cmd.Flags().GetBool("yes")

			switch {
			case mustBool(cmd, "check"):
				return runHookCheck(out, path)
			case mustBool(cmd, "uninstall"):
				if !yes {
					fmt.Fprintf(out, "would remove warden's hook entry from %s\n"+
						"re-run with --yes to apply it\n", path)
					return nil
				}
				removed, err := hook.Uninstall(path)
				if err != nil {
					return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
				}
				if !removed {
					fmt.Fprintf(out, "ok: no warden hook entry in %s\n", path)
					return nil
				}
				fmt.Fprintf(out, "ok: warden's hook entry removed from %s\n", path)
				return nil
			case mustBool(cmd, "install"):
				block, err := hook.EntryJSON(guardCommand)
				if err != nil {
					return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
				}
				if !yes {
					fmt.Fprintf(out, "would merge this into %s, leaving every other setting alone:\n\n%s\n\n"+
						"re-run with --yes to apply it\n", path, block)
					return nil
				}
				if err := hook.Install(path, guardCommand); err != nil {
					return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
				}
				fmt.Fprintf(out, "ok: warden's hook entry installed in %s\n", path)
				return nil
			}

			block, err := hook.EntryJSON(guardCommand)
			if err != nil {
				return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
			}
			fmt.Fprintln(out, block)
			return nil
		},
	}
	cmd.Flags().Bool("install", false, "merge the hook entry into the settings file")
	cmd.Flags().Bool("uninstall", false, "remove warden's hook entry")
	cmd.Flags().Bool("check", false, "report whether the hook is installed and warden is on PATH")
	cmd.Flags().Bool("guard", false, "decide one tool call, reading the payload on stdin (used by the hook)")
	cmd.Flags().Bool("yes", false, "apply the change instead of describing it")
	cmd.Flags().String("settings", "", "settings file to act on (default: the harness's own)")
	cmd.Flags().String("target", "claude", "which harness to write settings for")
	root.AddCommand(cmd)
}

func mustBool(cmd *cobra.Command, name string) bool {
	v, _ := cmd.Flags().GetBool(name)
	return v
}

// settingsPath resolves which settings file to act on. --global targets the
// user's, anything else the project's.
func settingsPath(cmd *cobra.Command) (string, error) {
	if explicit, _ := cmd.Flags().GetString("settings"); explicit != "" {
		return explicit, nil
	}
	if global, _ := cmd.Flags().GetBool("global"); global {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".claude", "settings.json"), nil
	}
	dir, _ := cmd.Flags().GetString("project")
	if dir == "" {
		var err error
		if dir, err = os.Getwd(); err != nil {
			return "", err
		}
	}
	return filepath.Join(dir, ".claude", "settings.json"), nil
}

// runGuard decides one tool call. Exit 2 is warden's "refused by policy", and
// also how a harness reads a blocked call — the two meanings coincide exactly.
// With --json the decision is also written to stdout, and the reason travels
// there instead of on stderr.
//
// Every failure here fails open. A guard that cannot parse its payload must not
// block every tool call in the session; a hook that breaks a working harness
// gets deleted, and then nothing is guarded at all.
func runGuard(out io.Writer, asJSON bool) error {
	d := decideGuard()
	if asJSON {
		answer := guardAnswer{Decision: "allow"}
		if d.Reason != "" {
			answer = guardAnswer{Decision: "deny", Target: string(d.Target), Reason: d.Reason}
		}
		if err := json.NewEncoder(out).Encode(answer); err != nil {
			return nil
		}
		if d.Reason != "" {
			return &ExitError{Code: CodeRefused}
		}
		return nil
	}
	if d.Reason == "" {
		return nil
	}
	return &ExitError{Code: CodeRefused, Msg: d.Reason}
}

// decideGuard reads the payload and decides it; anything unreadable allows.
func decideGuard() hook.Decision {
	body, err := io.ReadAll(GuardInput)
	if err != nil {
		return hook.Decision{}
	}
	var p guardPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return hook.Decision{}
	}
	// Each tool names its file in a field of its own; Decide only needs to
	// know which one this call used.
	path := p.ToolInput.FilePath
	for _, alt := range []string{p.ToolInput.NotebookPath, p.ToolInput.LSPPath, p.ToolInput.Path} {
		if path == "" {
			path = alt
		}
	}
	req := hook.Request{
		ToolName: p.ToolName,
		FilePath: path,
		Command:  p.ToolInput.Command,
		Glob:     p.ToolInput.Glob,
	}
	d := hook.Detail(req)
	// ln -s .env notes.txt, then Read notes.txt: the name says nothing, where it
	// lands says everything. A path that resolves nowhere is judged by its name.
	if d.Reason == "" && path != "" {
		if real, err := filepath.EvalSymlinks(path); err == nil && real != path {
			req.FilePath = real
			d = hook.Detail(req)
		}
	}
	return d
}

func runHookCheck(out io.Writer, path string) error {
	installed := hook.Installed(path)
	if installed {
		fmt.Fprintf(out, "hook:    installed in %s\n", path)
	} else {
		fmt.Fprintf(out, "hook:    not installed in %s\n", path)
	}

	// A hook that denies `cat .env` and recommends a command that is not
	// installed is strictly worse than no hook.
	bin, err := LookWarden()
	if err != nil {
		fmt.Fprintln(out, "warden:  NOT on PATH — the denial would name a command that does not run")
		return &ExitError{Code: CodeNo}
	}
	fmt.Fprintf(out, "warden:  %s\n", bin)

	if err := GuardProbe(bin); err != nil {
		fmt.Fprintf(out, "guard:   the warden on PATH is too old to run `hook --guard`\n"+
			"         every tool call would be allowed while the hook looks installed.\n"+
			"         reinstall warden so PATH has this version.\n")
		return &ExitError{Code: CodeNo}
	}
	fmt.Fprintf(out, "guard:   runs\n")
	fmt.Fprintf(out, "matcher: %s\n", hook.Matcher)
	if !installed {
		return &ExitError{Code: CodeNo}
	}
	return nil
}
