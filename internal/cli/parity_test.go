package cli

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"

	"github.com/webteractive/warden/internal/mcpserver"
)

// commandNames lists every leaf command, descending one level into a family so
// `vault push` is accounted for rather than hidden behind `vault`.
func commandNames(root *cobra.Command) []string {
	var out []string
	for _, c := range root.Commands() {
		if c.Name() == "help" || c.Name() == "completion" {
			continue
		}
		if c.HasSubCommands() {
			for _, sub := range c.Commands() {
				if sub.Name() == "help" || sub.Name() == "completion" {
					continue
				}
				out = append(out, c.Name()+" "+sub.Name())
			}
			continue
		}
		out = append(out, c.Name())
	}
	return out
}

// parity records how each CLI command is covered on the MCP surface. An empty
// string is a deliberate omission and must carry a reason: the design promises
// the two surfaces cannot drift apart in what they will and will not reveal, and
// this table is the only thing that makes that mechanical rather than customary.
//
// env_doctor was missing for an entire release because nothing checked.
var parity = map[string]string{
	"has":      "env_has",
	"list":     "env_list",
	"get":      "env_get",
	"missing":  "env_missing",
	"classify": "env_classify", // --set is CLI-only: an agent may ask a key's class, never change it
	"doctor":   "env_doctor",
	// Exposed on purpose, unlike the other file-shaping commands. An agent that
	// cannot call this creates the file some other way — touch, a redirect, a
	// copy of .env.example — and every one of those applies the umask and leaves
	// the credentials readable by every account on the machine. It reveals
	// nothing and destroys nothing, so the safe path is the available one.
	"init":  "env_init",
	"set":   "env_set", // plus env_request_secret for --secret
	"unset": "env_unset",
	"clear": "env_clear",
	"refs":  "env_refs",
	"mcp":   "", // the server itself; there is nothing to mirror
	// No tool, because MCP already answers this: the server reports its version
	// in the initialise handshake, so a client has the number before it could
	// call anything. internal/buildinfo is the single source both read.
	"version": "",
	// Deliberately CLI-only. A tool that edits the harness's own permission
	// configuration is a privilege-escalation primitive, and an agent asking to
	// relax its own restrictions is precisely what this hook exists to stop.
	"hook": "",

	"vault set":  "vault_request_secret", // the value always comes from a prompt; there is no vault_set
	"vault list": "vault_list",
	"vault has":  "vault_has",
	"vault rm":   "vault_delete",
	"vault push": "vault_push",
	// Deliberately CLI-only. An agent quietly extending a credential's TTL is
	// exactly the operation this surface should not offer.
	"vault edit": "",
	// Deliberately CLI-only. init chooses how the vault is protected at rest —
	// the same class of decision as hook editing the harness's own permissions.
	"vault init": "",
}

// toolOwners inverts parity, naming which command each tool answers for.
func toolOwners() map[string]string {
	owners := map[string]string{
		// Not commands of their own: the value always arrives through a prompt.
		"env_request_secret":   "set --secret",
		"vault_request_secret": "vault set",
	}
	for cmd, tool := range parity {
		if tool != "" {
			owners[tool] = cmd
		}
	}
	return owners
}

func TestEveryCommandIsAccountedForOnTheMCPSurface(t *testing.T) {
	root := newRootCmd(&bytes.Buffer{}, &bytes.Buffer{})
	for _, name := range commandNames(root) {
		if _, ok := parity[name]; !ok {
			t.Errorf("command %q has no entry in the parity table — add the MCP tool that covers it, "+
				"or map it to \"\" with a comment saying why it is deliberately CLI-only",
				name)
		}
	}
}

func TestEveryMCPToolIsAccountedForOnTheCLISurface(t *testing.T) {
	owners := toolOwners()
	for _, name := range mcpserver.ToolNames() {
		if _, ok := owners[name]; !ok {
			t.Errorf("MCP tool %q answers for no CLI command — add it to the parity table", name)
		}
	}
}
