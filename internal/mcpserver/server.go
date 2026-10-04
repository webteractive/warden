// Package mcpserver exposes Warden's query and write surfaces as MCP tools.
//
// It is a thin translation layer over internal/query and internal/write — the
// same code the CLI drives — so the two surfaces cannot drift apart in what
// they will and will not reveal.
package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/webteractive/warden/internal/prompt"
	"github.com/webteractive/warden/internal/query"
	"github.com/webteractive/warden/internal/write"
)

// scopeArgs are the fields every tool accepts. The MCP server's working
// directory will not reliably match the project under discussion, so callers
// name it explicitly.
type scopeArgs struct {
	Project string `json:"project,omitempty" jsonschema:"directory to search for .env; defaults to the server's working directory"`
	Global  bool   `json:"global,omitempty" jsonschema:"target ~/.secrets instead of a project .env"`
}

func (a scopeArgs) scope() query.Scope {
	dir := a.Project
	if dir == "" {
		dir, _ = os.Getwd()
	}
	home, _ := os.UserHomeDir()
	return query.Scope{Global: a.Global, Dir: dir, Home: home}
}

type keyArgs struct {
	scopeArgs
	Key string `json:"key" jsonschema:"the environment variable name"`
}

type refsArgs struct {
	scopeArgs
	IncludeVendor bool `json:"includeVendor,omitempty" jsonschema:"walk vendor and node_modules too"`
}

type setArgs struct {
	scopeArgs
	Key   string `json:"key" jsonschema:"the environment variable name"`
	Value string `json:"value" jsonschema:"the value to write; rejected if the key or the value is sensitive"`
}

// The vault is user-global, so none of these carry a project or a scope — and
// none of them carries a `yes`. A push from an agent always confirms on the
// user's screen; that is not negotiable through an argument.
type vaultNameArgs struct {
	Name string `json:"name" jsonschema:"the vault entry's name"`
}

type vaultRequestArgs struct {
	Name string `json:"name" jsonschema:"the vault entry's name, e.g. stripe/live"`
	Key  string `json:"key,omitempty" jsonschema:"the env key it lands as; may be omitted when the name is already a valid env key"`
	TTL  string `json:"ttl,omitempty" jsonschema:"delete the entry after this long, e.g. 8h or 7d; maximum 30d; omit for permanent"`
}

type vaultPushArgs struct {
	Name    string `json:"name" jsonschema:"the vault entry to push"`
	Project string `json:"project,omitempty" jsonschema:"destination directory; defaults to the server's working directory"`
	Global  bool   `json:"global,omitempty" jsonschema:"push into ~/.secrets instead of a project .env"`
	As      string `json:"as,omitempty" jsonschema:"write it under a different env key"`
	Force   bool   `json:"force,omitempty" jsonschema:"overwrite a destination key that is already set"`
}

func homeDir() string {
	home, _ := os.UserHomeDir()
	return home
}

// promptFor returns the prompter New was given. The vault's passphrase mode and
// every confirmation route through it, so it must be the same channel the env
// tools use rather than a fresh default.
var promptFor = func() prompt.Prompter { return prompt.Default() }

func textResult(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

func errResult(format string, a ...any) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(format, a...)}},
	}
}

// ToolNames lists every tool New registers. It is hand-maintained and kept
// honest by a test that compares it against a live session, because
// internal/cli's parity check needs the list without importing the server's
// internals — and cli already imports this package, so the check cannot live on
// the other side.
func ToolNames() []string {
	return []string{
		"env_has", "env_list", "env_missing", "env_get", "env_doctor", "env_init",
		"env_set", "env_request_secret", "env_unset", "env_clear", "env_classify", "env_refs",
		// The vault. There is deliberately no vault_set (no entry is public),
		// no vault_edit and no vault_init (both CLI-only) — internal/cli's
		// parity table records each omission with its reason.
		"vault_list", "vault_has", "vault_request_secret", "vault_delete", "vault_push",
	}
}

// New builds the MCP server. p is the channel used to collect secret values.
func New(p prompt.Prompter) *mcp.Server {
	promptFor = func() prompt.Prompter { return p }
	s := mcp.NewServer(&mcp.Implementation{Name: "warden", Version: version}, nil)

	mcp.AddTool(s, &mcp.Tool{
		Name: "env_has",
		Description: "Report whether an environment key is set (present and non-empty). " +
			"Works for secret keys too — it never reveals the value. Use this instead of reading .env.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, a keyArgs) (*mcp.CallToolResult, any, error) {
		q, err := query.Open(a.scope())
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		set := q.Has(a.Key)
		return textResult(fmt.Sprintf("%t", set)), nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "env_list",
		Description: "List every key in the target file with its classification (public or secret) " +
			"and whether it is set. Values are never included.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, a scopeArgs) (*mcp.CallToolResult, any, error) {
		q, err := query.Open(a.scope())
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		type row struct {
			Key   string `json:"key"`
			Class string `json:"class"`
			Set   bool   `json:"set"`
		}
		rows := []row{}
		for _, r := range q.List() {
			rows = append(rows, row{r.Key, r.Class.String(), r.Set})
		}
		return nil, rows, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "env_init",
		Description: "Create the env file this scope writes to (.env, or ~/.secrets with global), " +
			"with permissions that let only its owner read it. Safe to re-run: an existing file " +
			"keeps its contents, and loose permissions on one are tightened. Use this instead of " +
			"creating .env yourself — touch, a shell redirect, or copying .env.example all apply " +
			"the umask and commonly leave a file of credentials readable by every account on the " +
			"machine.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, a scopeArgs) (*mcp.CallToolResult, any, error) {
		res, err := write.Create(a.scope())
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		return nil, map[string]any{
			"path":      res.Path,
			"created":   res.Created,
			"tightened": res.Tightened,
			"mode":      fmt.Sprintf("%04o", res.Mode),
		}, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "env_missing",
		Description: "List keys declared in .env.example that are absent or empty in .env. Project scope only.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, a scopeArgs) (*mcp.CallToolResult, any, error) {
		q, err := query.Open(a.scope())
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		keys, err := q.Missing()
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		if keys == nil {
			keys = []string{}
		}
		return nil, keys, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "env_get",
		Description: "Read the value of a PUBLIC key. Secret keys are refused — use env_has to check " +
			"whether one is set, or env_request_secret to have the user fill it in.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, a keyArgs) (*mcp.CallToolResult, any, error) {
		q, err := query.Open(a.scope())
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		v, err := q.Get(a.Key)
		switch {
		case errors.Is(err, query.ErrSecret):
			return errResult("warden: %s is secret — its value is not readable", a.Key), nil, nil
		case errors.Is(err, query.ErrNotSet):
			return errResult("warden: %s is not set", a.Key), nil, nil
		case err != nil:
			return errResult("warden: %v", err), nil, nil
		}
		return textResult(v), nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "env_set",
		Description: "Set a PUBLIC key's value. Refused if the key is classified secret, or if the " +
			"supplied value itself looks like a credential.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, a setArgs) (*mcp.CallToolResult, any, error) {
		w, err := write.Open(a.scope(), p)
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		if err := w.SetPublic(a.Key, a.Value); err != nil {
			if errors.Is(err, write.ErrSecretKey) {
				// The CLI offers --exposed here, and this surface deliberately
				// does not: accepting a value on the caller's terms is safe when
				// a human types the flag and is not safe as a tool call, which
				// internal/cli's arch test enforces. That makes it all the more
				// important to say what *is* available, because the value has
				// already crossed into the transcript by the time this is read —
				// a caller left without a next step writes the file by hand.
				return errResult(
					"warden: %s is secret, so it was not written. That value has already "+
						"crossed into this transcript. If the user holds it, call "+
						"env_request_secret so they type it into a prompt you never see. "+
						"If you already had it, it is burned: it needs `warden set --exposed "+
						"%s <value>` run at a terminal, which records the exposure, and the "+
						"credential should be rotated.",
					a.Key, a.Key), nil, nil
			}
			return errResult("warden: %v", err), nil, nil
		}
		return textResult(fmt.Sprintf("ok: %s set (public) in %s", a.Key, w.Path())), nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "env_request_secret",
		Description: "Ask the user to type a secret value into a prompt on their screen, and write it. " +
			"You never see the value — only a confirmation. Use this for any sensitive key.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, a keyArgs) (*mcp.CallToolResult, any, error) {
		w, err := write.Open(a.scope(), p)
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		if err := w.SetSecret(a.Key); err != nil {
			if errors.Is(err, prompt.ErrCancelled) {
				return errResult("warden: cancelled — nothing was written"), nil, nil
			}
			return errResult("warden: %v", err), nil, nil
		}
		return textResult(fmt.Sprintf("ok: %s set (secret) in %s", a.Key, w.Path())), nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "env_doctor",
		Description: "Report what is wrong with the target file: permissions, keys declared but " +
			"empty, and keys .env.example declares that .env does not set. Ask this first about an " +
			"unfamiliar project. Values are never included.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, a scopeArgs) (*mcp.CallToolResult, any, error) {
		q, err := query.Open(a.scope())
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		problems := q.Doctor()
		if problems == nil {
			problems = []query.Problem{}
		}
		return nil, problems, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "env_unset",
		Description: "Remove a key entirely, including every duplicate assignment of it. Works on " +
			"secret keys — deleting reveals nothing. The user authorises it in a prompt on their " +
			"screen when the key currently holds a value.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, a keyArgs) (*mcp.CallToolResult, any, error) {
		w, err := write.Open(a.scope(), p)
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		n, err := w.Unset(a.Key)
		if res := removalError(err, a.Key, w.Path()); res != nil {
			return res, nil, nil
		}
		return textResult(fmt.Sprintf("ok: %s removed (%d assignment(s)) from %s", a.Key, n, w.Path())), nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "env_clear",
		Description: "Empty a key's value while leaving it declared, so it still appears in env_list " +
			"as unset. Use env_unset to remove it entirely.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, a keyArgs) (*mcp.CallToolResult, any, error) {
		w, err := write.Open(a.scope(), p)
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		if res := removalError(w.Clear(a.Key), a.Key, w.Path()); res != nil {
			return res, nil, nil
		}
		return textResult(fmt.Sprintf("ok: %s cleared in %s", a.Key, w.Path())), nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "env_classify",
		Description: "Explain whether a key is treated as public or secret, and which rule decided it.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, a keyArgs) (*mcp.CallToolResult, any, error) {
		q, err := query.Open(a.scope())
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		r := q.Classify(a.Key)
		return nil, map[string]string{"key": a.Key, "class": r.Class.String(), "rule": r.Rule}, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "env_refs",
		Description: "Compare the source tree against the env file. Returns keys the code reads that " +
			"are not set (undeclared — a real setup failure) and keys that are set but referenced " +
			"nowhere (unused — advisory only, since a key built at runtime looks identical). Better " +
			"than env_missing when .env.example is stale. Project scope only.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, a refsArgs) (*mcp.CallToolResult, any, error) {
		q, err := query.Open(a.scope())
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		rep, err := q.Refs(query.RefOptions{IncludeVendor: a.IncludeVendor})
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		type unused struct {
			Key   string `json:"key"`
			Class string `json:"class"`
		}
		payload := struct {
			Undeclared []query.Reference `json:"undeclared"`
			Unused     []unused          `json:"unused"`
		}{Undeclared: []query.Reference{}, Unused: []unused{}}
		payload.Undeclared = append(payload.Undeclared, rep.Undeclared...)
		for _, r := range rep.Unused {
			payload.Unused = append(payload.Unused, unused{r.Key, r.Class.String()})
		}
		return nil, payload, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vault_list",
		Description: "List the user's vault entries: each entry's name, the env key it lands as, " +
			"when it was stored, and when it expires. Values are never included, and there is no " +
			"tool that reads one — vault_push is how a value reaches a project.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		q, err := query.OpenVault(homeDir(), promptFor())
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		type row struct {
			Name      string `json:"name"`
			Key       string `json:"key"`
			Created   string `json:"created"`
			Expires   string `json:"expires,omitempty"`
			Permanent bool   `json:"permanent"`
		}
		rows := []row{}
		for _, r := range q.List() {
			out := row{Name: r.Name, Key: r.Key, Created: r.Created.UTC().Format(time.RFC3339),
				Permanent: r.Permanent}
			if !r.Permanent {
				out.Expires = r.Expires.UTC().Format(time.RFC3339)
			}
			rows = append(rows, out)
		}
		return nil, rows, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vault_has",
		Description: "Report whether the vault holds a live entry under this name. An expired entry " +
			"reads as absent. Never reveals a value.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, a vaultNameArgs) (*mcp.CallToolResult, any, error) {
		q, err := query.OpenVault(homeDir(), promptFor())
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		return textResult(fmt.Sprintf("%t", q.Has(a.Name))), nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vault_request_secret",
		Description: "Ask the user to type a value into a prompt and store it in the vault under a " +
			"name. The value never passes through this tool — you supply the name, the key it lands " +
			"as, and optionally a ttl. There is no vault_set: no vault entry is public.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, a vaultRequestArgs) (*mcp.CallToolResult, any, error) {
		key := a.Key
		if key == "" {
			if !query.LooksLikeEnvKey(a.Name) {
				return errResult(
					"warden: %s is not a usable env key, so key is required", a.Name), nil, nil
			}
			key = a.Name
		}
		var ttl time.Duration
		if a.TTL != "" {
			var err error
			if ttl, err = query.ParseTTL(a.TTL); err != nil {
				return errResult("warden: %v", err), nil, nil
			}
		}
		w, err := write.OpenVault(homeDir(), promptFor())
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		if err := w.Set(a.Name, key, ttl); err != nil {
			if errors.Is(err, prompt.ErrCancelled) {
				return errResult("warden: cancelled — nothing was written"), nil, nil
			}
			return errResult("warden: %v", err), nil, nil
		}
		return textResult(fmt.Sprintf("stored %s (lands as %s)", a.Name, key)), nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vault_delete",
		Description: "Remove a vault entry. The user authorises it on their screen first, because " +
			"the value may not be recoverable from anywhere else.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, a vaultNameArgs) (*mcp.CallToolResult, any, error) {
		w, err := write.OpenVault(homeDir(), promptFor())
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		if err := w.Remove(a.Name); err != nil {
			if errors.Is(err, prompt.ErrCancelled) {
				return errResult("warden: cancelled — nothing was removed"), nil, nil
			}
			return errResult("warden: %v", err), nil, nil
		}
		return textResult(fmt.Sprintf("removed %s", a.Name)), nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vault_push",
		Description: "Write a vault entry's value into a project's .env (or ~/.secrets). This is the " +
			"only way a value leaves the vault, and it always asks the user on their screen first — " +
			"it moves a credential into a file that may well be committed. The value is never " +
			"returned to you.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, a vaultPushArgs) (*mcp.CallToolResult, any, error) {
		w, err := write.OpenVault(homeDir(), promptFor())
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		dest := scopeArgs{Project: a.Project, Global: a.Global}.scope()

		// yes is false, always. There is no argument that can change it.
		res, err := w.Push(a.Name, dest, a.As, a.Force, false)
		if err != nil {
			if errors.Is(err, prompt.ErrCancelled) {
				return errResult("warden: cancelled — nothing was written"), nil, nil
			}
			return errResult("warden: %v", err), nil, nil
		}
		return textResult(fmt.Sprintf("pushed %s as %s into %s", a.Name, res.Key, res.Path)), nil, nil
	})

	return s
}

// removalError renders the failures env_unset and env_clear share, and nil when
// there was none.
func removalError(err error, key, path string) *mcp.CallToolResult {
	switch {
	case errors.Is(err, write.ErrAbsent):
		return errResult("warden: %s is not present in %s", key, path)
	case errors.Is(err, prompt.ErrCancelled):
		return errResult("warden: cancelled — nothing was written")
	case err != nil:
		return errResult("warden: %v", err)
	}
	return nil
}

// Serve runs the server on stdio.
func Serve(ctx context.Context, p prompt.Prompter) error {
	return New(p).Run(ctx, &mcp.StdioTransport{})
}
