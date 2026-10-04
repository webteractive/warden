// Package cli is the command-line surface.
//
// It imports query and write, and never store — so no command can reach a raw
// value without going through a classification. internal/cli/arch_test.go
// enforces that mechanically.
package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/webteractive/warden/internal/buildinfo"
	"github.com/webteractive/warden/internal/mcpserver"
	"github.com/webteractive/warden/internal/query"
)

// ExitError carries a process exit code. An empty Msg prints nothing, which is
// how `has` reports a negative answer silently.
type ExitError struct {
	Code int
	Msg  string
	// Kind is the machine-readable cause a --json caller keys on. Empty means
	// the default for Code (see kindOf).
	Kind string
}

func (e *ExitError) Error() string { return e.Msg }

// Exit codes. These are the contract callers script against.
const (
	CodeOK      = 0 // success
	CodeNo      = 1 // key absent or unset
	CodeRefused = 2 // refused by policy: the key is secret
	CodeError   = 3 // no env file, parse failure, cancelled prompt
)

// ExitCode maps an error from Run to a process exit code.
func ExitCode(err error) int {
	if err == nil {
		return CodeOK
	}
	var ee *ExitError
	if errors.As(err, &ee) {
		return ee.Code
	}
	return CodeError
}

// Run executes the CLI against args. It is the testable seam: tests drive it
// with in-memory writers rather than spawning a process.
//
// Run also writes the error message to errw rather than leaving that to main.
// Error text is output like any other, and it must be covered by the canary
// leak test — which only sees what Run writes. Printing from main instead would
// leave every failure path untested.
func Run(args []string, out, errw io.Writer) error {
	root := newRootCmd(out, errw)
	root.SetArgs(args)
	root.SetOut(out)
	root.SetErr(errw)

	err := root.Execute()
	if err != nil {
		if msg := err.Error(); msg != "" {
			if jsonRequested(root, args) {
				writeJSONError(errw, err)
			} else {
				fmt.Fprintln(errw, msg)
			}
		}
	}
	return err
}

// jsonRequested reports whether the caller asked for --json. The parsed flag is
// the answer once cobra got that far; a usage error can stop it earlier, and
// the raw arguments still say what was asked for.
func jsonRequested(root *cobra.Command, args []string) bool {
	if v, err := root.PersistentFlags().GetBool("json"); err == nil && v {
		return true
	}
	for _, a := range args {
		if a == "--json" || a == "--json=true" {
			return true
		}
	}
	return false
}

// writeJSONError writes an error as {"error":{"code","message"}} so a program
// can branch on the cause. The message is the same text a person would see,
// which carries no value for the same reasons the plain form does.
func writeJSONError(errw io.Writer, err error) {
	type body struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	_ = json.NewEncoder(errw).Encode(map[string]body{
		"error": {Code: kindOf(err), Message: err.Error()},
	})
}

// kindOf names an error's cause: its own Kind, else the meaning of its exit
// code. An error that is not an ExitError came from argument parsing.
func kindOf(err error) string {
	var ee *ExitError
	if !errors.As(err, &ee) {
		return "usage"
	}
	if ee.Kind != "" {
		return ee.Kind
	}
	switch ee.Code {
	case CodeNo:
		return "not-set"
	case CodeRefused:
		return "refused"
	default:
		return "error"
	}
}

func newRootCmd(out, errw io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "warden",
		Short:         "warden — check and edit env configuration without exposing secrets",
		Version:       buildinfo.String(),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	addVersionSpellings(root, out)
	root.PersistentFlags().Bool("global", false, "operate on ~/.secrets instead of a project .env")
	root.PersistentFlags().String("project", "", "directory to search for .env (default: current directory)")
	root.PersistentFlags().Bool("json", false, "emit machine-readable JSON")

	addReadCommands(root, out)
	addHookCommand(root, out)
	addInitCommand(root, out)
	addWriteCommands(root, out)
	addVaultCommands(root, out)

	root.AddCommand(&cobra.Command{
		Use:   "mcp",
		Short: "run the MCP server on stdio",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := mcpserver.Serve(cmd.Context(), SetPrompter); err != nil {
				return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
			}
			return nil
		},
	})
	return root
}

// addVersionSpellings makes every reasonable way of asking "which build is
// this?" work.
//
// Setting Version gives cobra `--version` for free; the rest is the two other
// spellings people actually type. Which one a caller reaches for is not worth
// guessing at: an install check, a bug report and a support thread will each try
// a different one, and the cost of answering all three is a few lines. warden
// previously answered none of them — `warden --version` said "unknown flag",
// which reads as a broken binary to every script that asks.
//
// The answer goes to stdout and exits 0. It is a successful answer to a
// question, not a diagnostic, and the scripts that ask are the main caller.
func addVersionSpellings(root *cobra.Command, out io.Writer) {
	root.SetVersionTemplate("warden {{.Version}}\n")
	// -v is free here: warden has no verbose flag for it to collide with.
	root.Flags().BoolP("version", "v", false, "print the version and exit")

	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "print the version and exit",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			fmt.Fprintf(out, "warden %s\n", buildinfo.String())
			return nil
		},
	})
}

// scopeFrom builds a query.Scope from the persistent flags.
func scopeFrom(cmd *cobra.Command) query.Scope {
	global, _ := cmd.Flags().GetBool("global")
	dir, _ := cmd.Flags().GetString("project")
	if dir == "" {
		dir, _ = os.Getwd()
	}
	home, _ := os.UserHomeDir()
	return query.Scope{Global: global, Dir: dir, Home: home}
}

func jsonFlag(cmd *cobra.Command) bool {
	v, _ := cmd.Flags().GetBool("json")
	return v
}

// openQuery resolves the scope, translating a missing file into exit code 3.
func openQuery(cmd *cobra.Command) (*query.Q, error) {
	q, err := query.Open(scopeFrom(cmd))
	if err != nil {
		ee := &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
		if errors.Is(err, query.ErrNoFile) {
			ee.Kind = "no-env-file"
		}
		return nil, ee
	}
	return q, nil
}
