# warden for Claude Code

A Claude Code mod (a plugin of TypeScript function hooks) that brings warden
into the session. It never reads `.env` or `~/.secrets` itself, and never shows
a value: warden decides and holds the values, and this mod asks it.

| Feature | What it does |
|---|---|
| Guard | Denies `Read`, `Edit`, `Write`, `NotebookEdit`, `LSP`, `Grep`, `Bash` and `Monitor` calls that would read `.env*` or `.secrets`, for the main loop and subagents alike. Every such call is put to `warden hook --guard --json` as written, so the mod and the settings hook never disagree about how `.e""nv`, `.ENV` or a symlink should be read. |
| Tripwire | Scans every row the model reads that you did not type — tool results, Monitor events and task notifications, other agents' messages, settings-hook context — for credential shapes (warden's rules, unanchored; every rule linear, so megabytes of output scan in milliseconds). High-confidence live credentials are removed before the row is stored or sent; everything found is named to the model and to you, by rule — never by value. |
| Health band | Runs `warden doctor --json` for the project and `~/.secrets` at start, on a directory change, after a warden write and at most once a minute after turns. Shows warn-or-worse above the prompt, beneath nothing: other plugins' bands stay below it. A key left empty in a project's `.env`, or declared in `.env.example` and left out of it, is taken as meant: it stays off the band and `/env` shows it as `unset` with no badge. An empty key in `~/.secrets` shows in both. **Hide** holds for the session until the findings change. **Ask Claude to fix** fills the prompt without sending it. |
| `/env` | A pane of key names, class, set/unset and doctor badges. **Set…** and **Generate** run `warden set --secret KEY` (`--generate`), which opens warden's own macOS dialog; the value goes from your keyboard to the file and never through the session. `/env global` for `~/.secrets`, `/env refresh` to re-probe. |

This is a speed bump list plus a tripwire behind it, not containment. `python
-c`, a script written by a heredoc and run later, `grep -r TOKEN .` or a
dotenv-loading script all get past the
guard; the tripwire catches what it can recognise in their output.

## Requirements

warden with `hook --guard --json` and JSON errors (the build in this checkout).
The mod probes at session start; with no warden, or one too old, the guard runs
**degraded**: any call that might spell an env file — `env` or `secrets` in any
case, `$'…'` quoting, or a dotfile word with a wildcard, brace, quote or
backslash — is denied until warden is reinstalled, and everything else runs
untouched.

Set… and Generate need macOS (warden's dialog is `osascript`) and a surface on
this Mac; elsewhere the pane shows the command to run instead.

## Loading

```sh
claude --plugin-dir ~/AI/warden/integrations/claude-code           # one session
CLAUDE_CODE_PLUGIN_DIRS=~/AI/warden/integrations/claude-code       # every session, watched
```

## Options

| Option | Default | |
|---|---|---|
| `redact` | `live` | `live`, `all` or `off` (note only) |
| `band` | `true` | show the health band |
| `bandLevel` | `warn` | lowest severity the band shows |
| `wardenPath` | `""` | explicit binary; empty means `PATH`, then `~/.local/bin/warden` |

There is no option to turn the guard off: settings are a file the model can
edit. Remove the plugin instead.

## Checking it

```sh
claude plugin validate integrations/claude-code
claude plugin test integrations/claude-code
go test ./internal/classify -run TheMod   # every warden shape has a tripwire rule
```

Type-check with the `tsconfig.json` from the header of the engine's
`claude-code.d.ts`, kept outside this folder (Claude Code writes its own
`tsconfig.json` and `.claude-plugin/types/` here when it loads the mod; both
are gitignored).

Everything that touches `$` lives in `hooks/register.tsx`, as top-level
functions: the engine follows `$` into nothing else. `guard.ts`, `health.ts`
and `shapes.ts` are pure.

Design: `docs/superpowers/specs/2026-10-04-warden-claude-mod-design.md`.
