# Warden — a Claude Code mod: the guard, the tripwire, and the env in view

**Date:** 2026-10-04
**Status:** implemented 2026-10-04 (W1–W4 and the mod; W5 deferred)

## Problem

Warden reaches Claude Code three ways today, and each one leaves a gap.

- **The rules** (`rules/warden.md`, the Environment files and Secrets file rules) are prose. The
  model follows them most of the time, and following them most of the time is not the same as
  following them.
- **`warden hook`** turns the read ban into a `PreToolUse` refusal, and it works. But it is **not
  installed** on this machine (`warden hook --check` exits 1), and a settings hook can only answer
  allow or deny. It cannot see what a tool *returned*, cannot draw anything, and has to start a
  process on every Read, Edit, Write and Bash call.
- **`warden mcp`** and the CLI answer questions when the model thinks to ask them. Nobody asks
  `warden doctor` at the start of a session, so a world-readable `.env`, a key marked `exposed` or
  a key that `.env.example` declares but `.env` never sets stays unnoticed until something breaks.

Claude Code mods (plugins of TypeScript function hooks that run inside the session and reload
when saved) close all three gaps from one place. A `tool.call` hook can deny before the call runs
*and* inspect what it returned. A `session.append` hook can change a tool result before it is
stored or sent. `ui.render` draws a band above the prompt and a pane. `$.process.run` reaches the
warden binary without a shell.

This spec designs that mod. It covers four features: the guard, the leak tripwire, the health
band and the `/env` pane. It also covers the small warden changes the mod needs, so that the
policy stays in Go and the mod is a thin client.

## Goals

1. Deny a direct read of `.env*` or `.secrets` by the model or any subagent, through every built-in
   tool that can perform one, and have the denial name the warden command to use instead.
   `~/.secrets` is refused with no override of any kind.
2. Notice when a tool result contains something shaped like a credential, tell both the person and
   the model, and by default keep high-confidence live credentials out of the model's context and
   out of the request sent to the API.
3. Show the person problems with the environment (permissions, `exposed` records, empty keys,
   drift from `.env.example`) without being asked, and stay silent when there are none.
4. Give the person one place to see every key's name, class and set/unset state, never a value,
   and to fill in a secret through warden's own dialog.
5. Keep one source of truth. The matcher table, the denial text and the value-shape rules stay in
   warden's Go code, where their tests already live. The mod calls warden for them and does not
   copy them.

## Non-goals

- **Containment.** This is the same speed-bump list `warden hook` is, plus a tripwire behind it.
  `python -c`, a heredoc, `grep -r TOKEN .`, a dotenv-loading build script and an MCP filesystem
  server all get past the guard. The mod must never describe itself as security. The invariants
  and tests below enforce that the same way `hook` does.
- Replacing the rules. They stay in force. The mod is the mechanical layer under them.
- Showing values in any form. That includes public keys, partial values and hashes.
- Writing `.env` itself. Every write goes through a warden command.
- Guarding MCP tools, the person's own `!` commands, or other harnesses (Codex, Cursor).
- Removing `warden hook`. It stays as the option for sessions that load no mods (`claude -p`
  without the plugin, other machines). See Risks for what happens when both run.

## Overview

```
                    ┌──────────────────────── warden mod (TypeScript, in-session) ────────────────────────┐
 tool call ───────▶ │ tool.call  ── prefilter ──▶ $.process.run(warden hook --guard --json) ──▶ deny/pass │
                    │      │                                                                               │
                    │      └── after next(e): warden write? ──▶ refresh health                             │
 tool result ─────▶ │ session.append(door: tool-result) ── shapes.ts scan ──▶ redact / note / toast        │
 session start ───▶ │ session.start, classic.CwdChanged, turn.complete ──▶ warden doctor --json (+global) │
                    │      └──▶ $.state 'warden'.health ──▶ ui.render AbovePrompt (band)                   │
 /env ────────────▶ │ command.run ──▶ $.ui.open Pane ──▶ warden list/doctor --json; Set ──▶ warden set     │
                    └──────────────────────────────────────────────────────────────────────────────────────┘
                                                   │ argv only, no shell
                                                   ▼
                                          ~/.local/bin/warden  (policy, matcher, shapes, values)
```

Values exist in two places only. The first is warden's own process. The second is the tool
output the tripwire scans, which was already in the session's memory before the mod saw it. The
mod never reads `.env` or `~/.secrets` with `$.fs.read`. It never puts a value in `$.state`,
`$.store`, a toast, a log line or a note. It also never passes a value to warden on a command
line.

## Prerequisite warden changes

The mod is only thin if warden can answer the questions it needs to ask. These changes come first
and each ships with Go tests.

| # | Change | Why the mod needs it |
|---|---|---|
| W1 | `hook --guard` reads more tool inputs: `NotebookEdit.notebook_path`, `Grep.path` and `Grep.glob` (a glob that could match `.env` or `.secrets` counts as naming one), and `Monitor.command` (judged as Bash). Unknown tools still pass. | The Go guard reads only `file_path` and `command` today. `Grep` (in builds that register it), `Monitor` and `NotebookEdit` walk past it. The settings hook gains coverage from this change too. |
| W2 | `hook --guard --json` writes `{"decision":"deny","target":"env"\|"secrets","reason":"…"}` to stdout on a deny and `{"decision":"allow"}` on an allow. The exit codes do not change: 2 means deny and 0 means allow. | Without it, the mod would need a regex to tell a `.secrets` refusal from a `.env` refusal for its own messages and counters. That regex would copy one already in Go. |
| W3 | Errors from `--json` commands become JSON on stderr, `{"error":{"code":"no-env-file","message":"…"}}`, with exit 3 as before. | The band has to tell "this project has no `.env`" (stay quiet) apart from "warden broke" (say so) without matching English text. |
| W4 | Reinstall: the binary on `PATH` predates `--version` and answers `unknown flag: --version`. | The mod checks the version at startup and refuses to use a guard older than W1/W2 (see Guard → Degraded mode). |
| W5 (later) | `warden scan --stdin --json` reads text on stdin and reports `[{rule, key?, start, end}]`, never the matched text. `key` is set when the text contains the actual value of a secret key in the project's `.env` or `~/.secrets`, found by the in-process Aho–Corasick matcher the `scan` spec already designs. | This is the tripwire's second stage. Shape rules catch `sk_live_…`. Only warden knows that a 32-character random string is your `SESSION_SECRET`. Passing tool output on stdin keeps values off `argv` and out of temp files, which the `scan` spec requires. |

W1 to W4 are small. W5 builds on the proposed `scan` spec and is not needed for the mod's first
release.

## Feature 1 — the guard

### Decision: reuse `warden hook --guard`, and don't reimplement it

The mod calls `warden hook --guard --json` through `$.process.run`, sending the tool call's payload
on stdin. The alternative was to port `internal/hook/decide.go` to TypeScript. Reuse wins because:

- **One matcher table.** `decide_test.go` has around forty rows of allow/deny decisions, each one
  something that would otherwise be argued over again. Two copies would drift, and the drift would
  be invisible because both copies would pass their own tests.
- **One denial text.** The guidance is long, carefully argued (the `--exposed` paragraph exists
  because of a specific failure), and tested for wording. The mod relays it unchanged.
- **The settings hook and the mod behave the same.** A session without the mod gets the same
  answer from `warden hook`.
- **The cost is small and limited to suspect calls.** A TypeScript prefilter (below) spawns warden
  only for calls whose input mentions `.env` or `.secrets`, which is a tiny fraction of tool calls.
  Waiting on `$.process.run` does not count against the 10-second hook budget.

Two things stay in TypeScript because the Go guard cannot do them from its side of a pipe:

1. **Symlink resolution.** `$.fs.stat(path, { resolve: true }).realPath` catches
   `ln -s .env notes.txt` followed by `Read notes.txt`. The engine docs say a deny-list on
   spellings is best effort and the robust form uses `realPath`.
2. **Behaviour when warden can't be run.** See Degraded mode.

### Events and matchers

```ts
on('tool.call', guardHook)            // no matcher: every tool, every loop (subagents carry agentId)
```

No matcher is used because the set of tools is per build. The native macOS build does not register
`Grep` or `Glob`. The hook switches on `String(e.tool)`:

| Tool | Fields forwarded | Notes |
|---|---|---|
| `Read`, `Edit`, `Write` | `file_path` | the given path, and the resolved `realPath` when they differ |
| `NotebookEdit` | `notebook_path` | needs W1 |
| `Grep` | `path`, `glob` | needs W1; registered only in some builds |
| `Bash` | `command` | `run_in_background` makes no difference |
| `Monitor` | `command` | needs W1; a monitor's stdout goes to the model as events |
| anything else | — | passed through without a spawn |

### Flow

```
guardHook($, e, next):
  1. pick the fields above; none → next(e)
  2. prefilter: none of the fields (nor the realPath) contains ".env" or ".secrets" → next(e)
  3. for path tools, stat(path, {resolve:true}); keep realPath if it differs (stat failure: skip it)
  4. run warden hook --guard --json with stdin = {tool_name, tool_input} (and again with the
     realPath substituted, when step 3 found one and the first answer was allow)
  5. exit 2 → return { deny: reason + suffix(target, tool) }
     exit 0 → next(e)
     anything else, or the spawn failed → degraded mode
```

The prefilter is a superset of warden's `envFileRe`: any call warden would deny contains the
literal `.env` or `.secrets`. Because of this, skipping the spawn never changes a decision.

The **suffix** is the only text the mod adds. It is one line that depends on the tool and the
target:

- target `secrets`: `~/.secrets is never readable, under any request. Add --global to the commands above.`
- `Write` or `Edit` on an env file: `To create the file: warden init (0600). To change keys: warden set, unset or clear.`

These lines should eventually move into warden's `Decide`, so the settings hook says them too.
That is follow-up F1.

### Overrides: none in v1

The brief asks about writes to `.env` that the user has explicitly authorised. The global
Environment files rule allows such writes. The mod nevertheless offers **no override in v1**:

- **Read** needs none. Every question a read answers, warden answers: `has`, `list`, `missing`,
  `doctor`, `classify` and `refs`.
- **Edit/Write** cannot be given a narrow override. Claude Code's Edit and Write tools refuse an
  existing file that has not been Read first in the session. Allowing an edit therefore means
  allowing a Read of every value in the file. A Bash `sed -i` on the file has the same problem,
  since warden's reader list counts `sed` as a reader.
- **Every write a user would authorise has a warden command.** `set`, `set --public`, `set
  --exposed`, `unset`, `clear` and `init` cover them. The person can also edit the file
  themselves with `! $EDITOR .env`, which does not go through `tool.call`.

This changes the effect of the global rule: the model can no longer edit `.env` directly even
when asked. Open question 1 asks the user whether that is acceptable, and sketches a
person-only, per-file, session-scoped grant in case it is not. `~/.secrets` is excluded from any
grant regardless of the answer.

### Degraded mode

At `session.start` the mod runs a probe:

1. Locate warden: `warden` on the session's `PATH`, else `$HOME/.local/bin/warden`, with `HOME`
   read through `$.env.get("HOME")`. A desktop-app session may not have `~/.local/bin` on its
   `PATH`.
2. Check the version with `warden --version`, and check the guard with `warden hook --guard
   --json` given `{}` on stdin, the same probe `hook --check` uses. Both must succeed.

If the probe fails, the guard runs **degraded**. Calls that pass the prefilter are denied with:

```
Denied: this call names .env or .secrets, and warden is not runnable here (<probe failure>), so it
cannot be checked. Reinstall warden (curl … install.sh | sh), then /env refresh.
```

Calls that don't pass the prefilter go through unchanged. One toast and a status line
(`warden: guard degraded`) tell the person.

This is the opposite of the Go guard's fail-open choice, and on purpose. The Go guard fails open
because a guard that blocks every tool call gets deleted. The degraded mod blocks only calls that
name an env file, which is narrow enough to live with. Failing open here would mean a stale
binary silently allows `cat ~/.secrets`. `hook`'s release notes record exactly that happening on
this machine.

### State

`warden.guard`: `{ mode: 'warden' | 'degraded', binary?: string, version?: string, reason?: string,
denies: { env: number, secrets: number } }`. The pane footer draws this record. The deny counts
are for the person's information and are never sent to the model.

## Feature 2 — the leak tripwire

### Where it runs: `session.append`, door `tool-result`

```ts
on('session.append', { door: 'tool-result' }, tripwire)
on('session.append', { door: 'tool-message' }, tripwire)   // rows a tool hands over
```

`session.append` is the one place that can **rewrite a tool result before it is stored and before
the next request carries it**. It applies to every tool, MCP servers included, and to every
subagent's conversation. A `tool.call` hook sees `ran.text` too, but it can only change what is
stored by answering with its own `{ result }`, which has to match each tool's output schema. That
is per-tool knowledge the mod should not carry. `origin.tool` on the row tells the hook which tool
produced it, which is enough to word the note.

### Detection: `lib/shapes.ts`

Warden's `shapePrefixes` are **anchored** checks on a whole env value, for example
`strings.HasPrefix(value, "sk_live_")`. Tool output is free text, so the mod needs unanchored
token patterns with a minimum body length. Each rule keeps warden's rule name, so the person, the
model and `warden classify` all use the same name for the same thing:

| Rule (warden's name) | Free-text pattern | Confidence |
|---|---|---|
| `shape:stripe-live` | `\bsk_live_[A-Za-z0-9]{16,}` | live |
| `shape:stripe-restricted` | `\brk_live_[A-Za-z0-9]{16,}` | live |
| `shape:stripe-test` | `\bsk_test_[A-Za-z0-9]{16,}` | test |
| `shape:github-pat` | `\bgithub_pat_[A-Za-z0-9_]{22,}`, `\bghp_[A-Za-z0-9]{36}\b` | live |
| `shape:github-oauth` / `-server` | `\bgh[os]_[A-Za-z0-9]{36}\b` | live |
| `shape:slack-bot` / `-user` / `-app` | `\bxox[bp]-[A-Za-z0-9-]{10,}`, `\bxapp-[A-Za-z0-9-]{10,}` | live |
| `shape:aws-access-key` / `-temp-key` | `\b(AKIA\|ASIA)[A-Z0-9]{16}\b` | live |
| `shape:pem-block` | `-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----` | live |
| `shape:jwt` | `\beyJ[\w-]{10,}\.eyJ[\w-]{10,}\.[\w-]{10,}` | test |
| `shape:url-userinfo` | `\b[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@` with the password not a placeholder | live, or test when the host is `localhost` or `127.0.0.1` |

Two places where the free-text rules are deliberately narrower than warden's:

- **PEM blocks:** only `PRIVATE KEY`. Warden's `-----BEGIN` is right for an env value, where
  nobody stores a certificate by accident. In tool output, `openssl x509` and `curl -v` print
  public certificates all the time.
- **userinfo URLs:** there is a placeholder stoplist (`password`, `pass`, `secret`, `xxx`,
  `changeme`, `***`, `<…>`, `${…}`, `%s`). Every `.env.example` and README contains
  `postgres://user:password@localhost`.

Nothing is exempt, warden's own output included (see As built). Text over 4 MiB per block is
scanned in its first 4 MiB, the same cap `$.process.run` applies.

A **parity test** reads `../../internal/classify/rules.go` when it is present and fails if
`shapePrefixes` contains a prefix with no rule in `shapes.ts`. A new shape added to warden then
cannot be missed by the tripwire. When W5 lands, `shapes.ts` drops to a fallback for when warden
cannot be run, and `scan --stdin` becomes the primary detector.

### Decision: redact live credentials by default, note the rest

The brief asked whether to redact. These are the trade-offs:

| | Redact (rewrite the tool_result) | Note only |
|---|---|---|
| The API request | never carries the value; `session.append` rewrites before the row is "stored and sent after" | carries it in every later request until compaction |
| Transcript `.jsonl` row the model reads | redacted | holds the value |
| What remains on disk and screen | **the value stays** in the row's `toolUseResult` record (the docs say it is "stored as made") and in terminal scrollback | the same, plus the row |
| Model can repeat it into a reply, file or commit | no, it never had it | yes; only the rules stop it |
| Model can still do the job | mostly. It can't write an Edit whose `old_string` contains the value, so moving a hard-coded key into `.env` needs a line-addressed `sed` or the person's help | fully |
| False positives | cost real work: a test-fixture `sk_test_…` or a JWT under debug disappears | cost a line of noise |
| Which warden channel is correct afterwards | **not `--exposed`**: the model never held the value, so the rule's test ("did you have it before you ran the command?") answers no | `--exposed`: the model holds it |

The mod therefore **redacts the `live` rules and only notes the `test` rules**, controlled by a
`redact` option (`live` by default, `all`, or `off`). Redaction is the mechanical form of the
global rule "never print, echo, log or repeat a secret value". It is also the only option that
keeps the value out of the API request, which matters more than any other row in the table. The
cost falls on false positives, and the rules marked `live` were chosen to have very few.

The redaction marker sits where the value was:

```
[warden: redacted shape:stripe-live — 1 of 1 in this output]
```

### What the person and the model are told

All three messages give rule names and counts. None includes a value, part of a value or a hash.

- **Person, as a toast** (throttled to one per rule per 60 s):
  `warden: a Stripe live key appeared in Bash output — redacted for the model. Rotate it; it is still in scrollback and the transcript file.`
- **Person, as a transcript notice** (`$.ui.log`, which the model never reads): the same message,
  plus the tool and `tool_use_id`, so the person can find the row afterwards.
- **Model**, as a text block appended to the same row (text the hook adds to a tool-result row
  follows the tool results):
  - When redacted:
    `warden: 1 value shaped like shape:stripe-live was removed from this output before you saw it. You do not hold it — do not run anything to see it again, and do not use warden set --exposed for it. Tell the user it was printed and should be rotated at the provider; the replacement goes in with warden set --secret KEY (or --from-file PATH).`
  - When only noted:
    `warden: this output contains a value shaped like shape:jwt. You now hold it: never repeat it in a reply, file or commit. If it belongs in an env file, warden set --exposed KEY VALUE is the honest channel, since you already have it; if it is a live credential, tell the user to rotate it.`

### Prompts the person pastes (v1.1)

`prompt.submit` runs the same scan on what the person types, and only ever shows a toast. It never
redacts and never drops the prompt, because the person chose to send the text. The toast reminds
them that `warden set --secret KEY` would have kept the value out of the conversation. This is not
in v1 because it is easy to get wrong in an irritating way. Open question 4.

### State

`warden.leaks`: `{ total: number, redacted: number, byRule: Record<string, number> }`. These are
counts only. The pane footer draws them.

## Feature 3 — the health band

### Data

Two calls per check, made in parallel. Each has a 10 s timeout and its `cwd` set to
`$.session.cwd()`:

```
warden doctor --json             → Problem[] for the project's .env   (exit 3: no env file)
warden doctor --global --json    → Problem[] for ~/.secrets
```

`doctor` already includes what `missing` would report, as its `drift` code (`declared in
.env.example but not set`). The band therefore does not call `missing`. `Problem` is `{ code, key?,
severity, message, fix? }`. Warden guarantees that `message` and `fix` contain no value: for a
secret key, `fix` is the prompted `set --secret KEY`.

The band shows only problems at `warn` or above. `info` codes (`multiline`, `no-example`) never
appear. A project with no `.env` (exit 3, which W3 makes machine-readable) is silent, **unless**
`$.fs.stat('.env.example')` succeeds. In that case the band shows one synthetic row: `no .env —
warden init, then warden missing`. `stat` on `.env.example` is not a read of anything protected.

### When it checks

| Trigger | Event |
|---|---|
| Session start | `session.start`, after `next(e)` |
| Directory change | `classic.CwdChanged`. Classic events fire whether or not a settings hook is configured. |
| After a warden write by the model | `tool.call` on `Bash`, after `await next(e)`, when the command's first word is `warden` and its subcommand is `set`, `unset`, `clear`, `init`, `classify … --set` or `vault push` |
| After a pane action | the pane's own handler |
| Edits made outside the session | `turn.complete`, at most once every 60 s, scheduled with `$.clock.after` |
| On demand | `/env refresh` |

A module-level in-flight flag stops checks from overlapping. Losing that flag on a hot reload does
no harm.

### State and dismissal

- `warden.health`: `{ project: Problem[] | null, global: Problem[] | null, noEnvButExample: boolean,
  checkedAt: number, error?: string }`
- `warden.bandHiddenFor`: a fingerprint string, or `null`

The fingerprint is the sorted list of `scope:code:key` triples for the problems shown. **Hide**
stores the current fingerprint, and the band stays hidden until the fingerprint changes. A new
problem therefore brings the band back, while a problem already dismissed does not keep returning.
Dismissal lasts for the session. Open question 5 asks whether it should persist per project
through `$.store`.

### UI

`ui.render` on `{ component: 'AbovePrompt' }`. The band is one instance shared by every plugin,
and a hook that returns its own tree without calling `next(e)` hides every band beneath it (the
schedy and hydra mods draw there too). So the hook always composes: `const below = await next(e)`,
then returns `<Box flexDirection="column">{mine}{below}</Box>`. It returns `below` alone when there
are no problems or the band is hidden, and returns `next(e)` untouched while `e.props.hasSurvey` is
true. Warden's rows share `maxRows` with whatever is beneath them, so the hook sizes text to
`e.props.bodyColumns` and shows at most `min(3, maxRows - 1)` problem rows:

```
warden  .env: 2 problems · ~/.secrets: 1                                [ Open /env ] [ Hide ]
  error  perms    .env is 0644 — group or world readable          chmod 600 .env
  warn   drift    STRIPE_SECRET declared in .env.example, not set  warden set --secret STRIPE_SECRET
  … 1 more in /env
```

Severity is coloured with the theme's error and warning colours. The `fix` column is dimmed and
truncated, never wrapped. Doctor returns problems worst first, so the rows shown are the worst
ones. There is no "fix it" button that acts for the person. Open question 6 asks whether
**Ask Claude** (`$.prompt.fill` with "fix what warden doctor reports, using warden only", filling
the prompt but not submitting it) is wanted.

## Feature 4 — the `/env` pane

### Command

`session.start` registers `{ name: 'env', description: 'Keys, classes and health of this project\'s
env — never values', argumentHint: '[global|refresh]' }`. `command.run` with `{ command: 'env' }`
handles it:

- `/env`: opens the pane on the project scope with `$.ui.open({ id: 'warden-env', title: 'env' })`
- `/env global`: opens the pane on the `~/.secrets` scope
- `/env refresh`: runs the guard probe and a health check, and answers `{ text }` with a one-line
  summary. That text is read by the model, which is fine because it contains no values.

### Data

```
warden list --json [--global]   → [{ key, class: 'secret'|'public', set: boolean }]
warden doctor --json [--global] → Problem[]   (reused from health when fresh)
```

The pane joins the two by `key` to add badges: `drift`, `empty` and `exposed`.

`warden classify KEY --json` runs only when the person presses **Why** on the selected row. It is
one spawn per press, not one per row.

### UI

```
┌ env ─────────────────────────────────────────────────────────────────────┐
│ [ Project ]  [ Global ]                         ~/Herd/app/.env  (0600)   │
│                                                                           │
│   APP_NAME          public   set                                          │
│   APP_KEY           secret   set                                          │
│ ▸ STRIPE_SECRET     secret   unset   drift                                │
│   CF_API_TOKEN      secret   set     exposed                              │
│                                                                           │
│ STRIPE_SECRET   [ Set… ]  [ Generate ]  [ Why ]                           │
│   name:*SECRET* · Set opens a macOS dialog; the value never reaches here. │
│                                                                           │
│ guard: warden 0.1.6 · 0 denies   tripwire: 1 redacted   [ Refresh ]       │
└───────────────────────────────────────────────────────────────────────────┘
```

- Each row is a `plain` Button keyed by the key name. Tab or a click selects it, and selection
  goes into `warden.pane.selected`. The action bar applies to the selected row. That avoids a set
  of buttons on every row and the hotkey collisions they would bring.
- **Set…** (secret keys) runs `$.process.run(['<warden>', 'set', '--secret', KEY, ...scope], {
  timeoutMs: 180_000 })`, with no `stdin` and no value in argv. Warden opens its own `osascript`
  dialog, and when the key already holds a value its Authorise dialog appears first. Each dialog
  gives up after 60 s, so two dialogs plus some slack fit inside 180 s.
- **Generate** (secret keys) runs the same command with `--generate`. Warden asks for
  authorisation when the key already has a value. This is the button for an `exposed` key whose
  value the project mints itself (`APP_KEY`, session secrets). For provider-issued credentials the
  person rotates at the provider and then uses **Set…**.
- **Public keys** get no write button in v1. The pane shows `ask Claude: warden set KEY VALUE`.
  A typed-value `Input` would make the mod handle a value. It would be harmless for a public key,
  but it is a line the invariants currently don't cross. Open question 7.
- While a command runs, `warden.pane.pending = { key, action }`. The action bar then reads
  `waiting for the dialog on your screen…` and its buttons are disabled. When it finishes, a toast
  shows warden's first stdout line (`ok: STRIPE_SECRET set (secret) in .env`, which by warden's
  invariant contains no value), or `cancelled` on exit 3. The list and health then refresh.

### Does `osascript` work from `$.process.run`? Yes, with the same conditions as the Bash tool

`$.process.run` starts a child as the session's user without a shell. The Bash tool does the same
when the model runs `warden set --secret`, and that is the path the README documents as working.
That includes the `stdin=PIPE` case: warden only reads stdin when given `--stdin`, a fix made
because runners always pass a pipe. The dialog therefore appears under the same conditions.
**Verify this during build step 4** before relying on it. The conditions:

- **macOS with a GUI login session** (Terminal, Ghostty or the desktop app on the same Mac). Over
  SSH there is no window server, so `osascript` fails, warden reports `cancelled` (exit 3), and the
  pane says so.
- **Remote surfaces** (mobile, Remote Control): the dialog appears on the Mac, not where the person
  is looking. The pane checks `e.surface` and, away from terminal and desktop, replaces Set with
  the command text.
- **Linux:** warden falls back to a prompt on `/dev/tty`. Started from inside the TUI, that prompt
  would fight Claude Code for the terminal. The pane turns the write buttons off when `uname` is
  not `Darwin` and shows `! warden set --secret KEY` instead.

### State

`warden.pane`: `{ scope: 'project' | 'global', rows: Row[], selected: string | null, pending: {
key: string, action: 'set' | 'generate' } | null, why: { key: string, rule: string } | null }`.
Here `Row = { key, class, set, flags: string[] }`.

## Options (`userConfig`)

| Field | Type | Default | Meaning |
|---|---|---|---|
| `redact` | string, `live`/`all`/`off` | `live` | tripwire redaction level |
| `band` | boolean | `true` | show the health band |
| `bandLevel` | string, `warn`/`error` | `warn` | lowest severity the band shows |
| `wardenPath` | string | `""` | explicit binary; empty means search `PATH`, then `~/.local/bin` |

There is deliberately **no option to turn the guard off**. `pluginConfigs` lives in a settings
file the model can Edit, so a guard switch would give the model a way to disable the guard on
itself. Turning the guard off means removing the plugin. Risk R4 covers the same concern for the
plugin directory variable.

## File layout and where it lives

**Decision: inside the warden repo**, at `integrations/claude-mod/`, with a marketplace manifest
at the repo root.

```
warden/
  .claude-plugin/marketplace.json     { "plugins": [{ "name": "warden", "source": "./integrations/claude-mod" }] }
  integrations/claude-mod/
    .claude-plugin/plugin.json        name "warden", version tracking warden's, userConfig, "types"
    hooks/hooks.json                  { "modules": ["./register.tsx"] }
    hooks/register.tsx                wiring only: on(...) → lib/ and ui/
    lib/warden.ts                     locate + probe; guard(), doctor(), list(), classify(), set()
    lib/guard.ts                      field picking, prefilter, realPath, degraded mode
    lib/shapes.ts                     free-text rules, scan(), redact()
    lib/tripwire.ts                   session.append handler; notes; throttled toasts
    lib/health.ts                     check(), fingerprint(), triggers
    ui/band.tsx                       AbovePrompt
    ui/pane.tsx                       Pane 'warden-env'
    types/index.d.ts                  declare module 'claude-code' { interface PluginState { warden: … } }
    tests/*.test.ts
    README.md
  .gitignore                          + integrations/claude-mod/.claude-plugin/types/
```

Why the warden repo rather than dotfiles or `~/.claude/dev-mods`:

- The mod is a client of warden's command line and JSON output. A change to either belongs in the
  same commit as the mod's adjustment.
- The parity tests read `internal/classify/rules.go` and `internal/hook/decide_test.go` through
  relative paths, so they need the Go source alongside.
- It ships with the tool. A teammate who installs warden can install the mod from the same repo.
  `dotfiles/claude/plugins.txt` already uses the `<plugin>@<marketplace> <org/repo>` format, so
  the line is `warden@warden webteractive/warden`.

How it is loaded:

| Where | How | Why |
|---|---|---|
| This Mac (the author) | `CLAUDE_CODE_PLUGIN_DIRS=/Users/glenbangkila/AI/warden/integrations/claude-mod` in the `env` block of `dotfiles/claude/settings.json` (it must be user settings; project settings are never read for this) | The folder is watched, so a save reloads the module in the running session. `--plugin-dir` would work too, but only for one session. |
| Teammates and other machines | `claude plugin marketplace add webteractive/warden` then `claude plugin install warden@warden`, or the `plugins.txt` line above | runs the copy made at install; updated by `claude plugin update` |

Do not do both on the same machine: two plugins named `warden` would both guard, and the second
would be redundant. The dotfiles `env` entry should be added only where the clone exists. Open
question 3.

## Invariants

1. **The mod never reads a protected file.** No `$.fs.read` of `.env*` or `.secrets`, ever. The
   only filesystem calls are `stat` (for symlink resolution and `.env.example` existence). A test
   asserts that `claude plugin validate`'s report lists no `fs.read` call.
2. **No value leaves the scan.** A matched value never reaches `$.state`, `$.store`, `$.ui.toast`,
   `$.ui.log`, a note to the model, or the argv of a child process. Messages contain rule names and
   counts only. This is enforced by a test that searches every recorded side effect for the
   fixture value.
3. **No value on a command line.** The mod never builds a warden argv that contains a value. Set
   and Generate pass a key name and flags only.
4. **The mod never describes itself as security.** The same banned-word test as
   `TestNothingClaimsThisIsSecurity` runs over every string the mod can show or send:
   `secure`, `security boundary`, `prevents`, `protects you`.
5. **`~/.secrets` is never allowed.** No option, grant or degraded path lets a call naming
   `.secrets` through, apart from a call whose first word is `warden`.
6. **Policy lives in warden.** The mod does not decide allow or deny on its own, except in degraded
   mode, where it denies only.

## Testing

`claude plugin validate integrations/claude-mod` runs on every change, and from a new
`scripts/check.sh` (the repo has no Makefile) alongside `go test ./...`. `claude plugin test integrations/claude-mod` runs the
`tests/*.test.ts` files. The test's own `on('process.run', …)` hooks stand in for the engine and
return canned warden output, so most tests are hermetic. A second suite builds the real binary
(`go build -o $TMP/warden ./cmd/warden`) and runs against it with `wardenPath`. That suite is
skipped when Go is unavailable.

- **guard.test.ts.** Every row of `decide_test.go` goes through `$.tool.call` against the real
  binary, checking that the mod and the Go guard agree. Plus:
  - `Read notes.txt` where `notes.txt → .env` is denied (realPath)
  - `NotebookEdit` and `Monitor` rows (W1)
  - a `cat ~/.secrets` deny carries the `.secrets` suffix
  - in degraded mode (`process.run` rejects), `cat .env` is denied and `ls` is allowed **without a
    spawn**
  - an `agentId` call (subagent) is guarded like a main-loop call
- **tripwire.test.ts.** A Bash result containing a fake `sk_live_` token arrives redacted in the
  stored row, with the model note appended and one toast. A fake `sk_test_` token is noted but not
  redacted. With `redact: 'off'` nothing is redacted and the `--exposed` wording appears. The
  `postgres://user:password@localhost` placeholder produces no finding. A public `-----BEGIN
  CERTIFICATE-----` produces no finding. Results from `warden` commands are skipped. Invariant 2:
  the fixture value appears in no state, store, toast, log or note.
- **health.test.ts.** Doctor fixtures → `warden.health`. Exit 3 with an `.env.example` present
  gives the synthetic row, and without one gives silence. The fingerprint is stable across orderings.
  `classic.CwdChanged` triggers a check (raised through the test's `classic` noun). A model `Bash`
  `warden set …` triggers one. The `turn.complete` debounce holds (`mock.clock`).
- **band.test.ts.** For each of `['terminal', 'desktop'] as const`, mount `AbovePrompt`: problems
  draw a tree; none, `hasSurvey`, or hidden pass through to `next(e)`; a test hook beneath that
  draws its own band still appears below warden's rows (composition, not replacement); Hide followed by a new
  problem draws again; the tree stays within `bodyColumns`.
- **pane.test.ts.** For each surface: `/env` opens `warden-env`; pressing a row selects it;
  **Set…** produces exactly `['…/warden','set','--secret','STRIPE_SECRET']` with `timeoutMs >=
  150000` and no `stdin`; the pending state disables the buttons; exit 3 shows a `cancelled` toast;
  a public row has no write button; on a mobile surface, or when `uname` is not Darwin, the command
  text replaces the buttons.
- **parity.test.ts.** Each `shapePrefixes` prefix in `rules.go` has a rule in `shapes.ts`, and each
  `readableNames` entry in `decide.go` is allowed by the guard. Both checks are skipped when the
  Go files are absent (an installed copy).
- **words.test.ts.** Invariant 4.
- **Go side.** W1 adds rows to `decide_test.go`. W2 and W3 add `--json` golden tests. Hook coverage
  improves for settings-hook users at the same time.

Manual check before release, in a scratch project with a fake `.env`: run `/env` and **Set…** in
Ghostty and in the desktop app, and confirm the dialog appears, the value lands, and nothing about
it appears in the transcript.

## Risks

- **R1 — the redaction leaves copies.** `toolUseResult` in the `.jsonl` file and terminal
  scrollback still hold the value, so redaction narrows the exposure and does not remove it. The
  toast says so plainly and recommends rotation. If later testing shows that `tool.call` can
  safely return a rewritten Bash `result`, an option to rewrite the stored record too can be added
  for Bash (follow-up F2).
- **R2 — false-positive redaction blocks work.** A real-looking test fixture or a JWT under
  debugging disappears. JWT and `sk_test_` are therefore note-only, and `redact: off` is one
  config-menu change away. Each redaction also produces a transcript notice, so a confused turn
  can be traced to its cause.
- **R3 — two guards.** If `warden hook --install` is also active, every suspect call spawns warden
  twice and a deny says the same thing twice. That is harmless but noisy. The pane footer shows
  `settings hook: installed` (from `hook --check --global`'s exit code; it has no `--json` yet) so the person can remove one.
- **R4 — the model can disable the mod.** It can Edit `~/.claude/settings.json` to remove
  `CLAUDE_CODE_PLUGIN_DIRS`, or Edit the mod's own source, which hot-reloads. This is the
  speed-bump problem again, and the mod is no different from the settings hook in this respect.
  It is noted so nobody over-claims. A `tool.call` deny on Edits to the mod's own folder is cheap
  and could be added (follow-up F3), with the same honesty caveat.
- **R5 — API churn.** Function hooks are early access, and the declaration file is the authority
  for each build. `claude plugin validate` in the check script catches breakage before a session does.
- **R6 — spawn latency on suspect calls.** One Go process start (single-digit milliseconds) per
  call that mentions `.env`, and two in the rare symlink case. Unsuspect calls cost a regex test.
- **R7 — a stale binary.** The probe catches a binary without W1/W2 and runs the guard degraded
  rather than trusting it. Degraded mode is deliberately strict, so a stale install can't look
  healthy.
- **R8 — the dialog is unreachable.** Over SSH, on a remote surface or on Linux, Set falls back to
  showing the command text, as described above.

## Open questions for the user

1. **Should the guard block `.env` edits the user explicitly asked for?** The global rule allows
   them, and this design denies them (see Overrides) because an edit needs a Read first. The
   alternative is a person-only grant. A deny on Edit/Write/Read of a specific `.env*` file (never
   `.secrets`) would raise `$.ui.ask("Allow Claude to read and edit <path> for this session? Its
   values will be sent to the model.", ["No — use warden", "Allow this file"])`. A yes would be
   recorded per `realPath` in session state, and the dialog cannot be answered by the model. Is
   that wanted, and should the rule's wording change to match either way?
2. **Redaction default.** Is `live` (redact high-confidence live credentials before the model sees
   them) the right default, or should v1 ship with `off` (toast and note only)?
3. **Loading on this machine.** Should `CLAUDE_CODE_PLUGIN_DIRS` go into
   `dotfiles/claude/settings.json`, which every machine shares, with `dotfiles.sh` writing it only
   where `~/AI/warden` exists? Or should it be set by hand on this Mac, with other machines using
   the marketplace install?
4. **Pasted prompts.** Should the tripwire also toast when the person pastes something that looks
   like a credential into a prompt (v1.1), or is that patronising?
5. **Band dismissal.** Session-only (as designed), or remembered per project and finding set in
   `$.store`?
6. **"Ask Claude" button on the band.** It would fill, not submit, a prompt asking the model to fix
   the doctor findings with warden. Wanted?
7. **Public keys in the pane.** Should `/env` let the person type a public key's value (`warden set
   KEY VALUE`, or `--public` for a new key), or should the pane stay value-free and leave public
   writes to the model?
8. **The settings hook.** Once the mod is in use, should `warden hook` stay uninstalled on this
   Mac (the mod covers it), or be installed as well for `claude -p` runs that don't load mods?
9. **W5 (`scan --stdin`).** Should it be planned now as part of the `scan` spec, so the tripwire
   can report "this output contains the value of `SESSION_SECRET`"? That catches the secrets shape
   rules cannot see, at the cost of warden reading both stores on every scanned result.

## Suggested build order

Each step is usable on its own and is tested before the next one starts.

1. **Warden W1–W4.** Extend the guard's tool coverage, add `--json` to the guard and to error
   output, and reinstall. Go tests only. The settings hook benefits immediately.
2. **Skeleton and guard.** `plugin.json`, `hooks.json`, `register.tsx`, `lib/warden.ts` with the
   probe, and `lib/guard.ts` with degraded mode. Then `guard.test.ts`, `words.test.ts`, and the
   `decide_test.go` parity check against the real binary. Load it with `--plugin-dir` for a day
   before adding it to settings.
3. **Health band.** `lib/health.ts`, `ui/band.tsx`, the triggers, and dismissal. Band tests run on
   both surfaces.
4. **`/env` pane, read-only first.** Then add Set… and Generate after **manually confirming the
   osascript dialog from `$.process.run`** in the terminal and in the desktop app.
5. **Tripwire, note-only.** `lib/shapes.ts`, `lib/tripwire.ts` and `parity.test.ts`, with
   `redact: off` hard-wired. Use it for a while and count false positives in the transcript
   notices.
6. **Turn on redaction** at the default chosen in open question 2, along with the redacted-case
   wording.
7. **Distribution.** Add the root `marketplace.json` and the README section, then the
   `plugins.txt` line and the dotfiles env entry (open question 3).
8. **Later:** W5 `scan --stdin` (open question 9); F1, moving the deny suffixes into warden's
   `Decide`; F2, rewriting the stored Bash record; F3, guarding the mod's own folder; the
   pasted-prompt toast (open question 4).

## Out of scope

- Guarding MCP tools by name. A filesystem MCP server's `read_file` on `.env` is not covered, and
  matching every server's argument names is a project of its own. The tripwire still catches
  live-shaped values in their results.
- Rewriting a denied command into its warden equivalent. The `hook` spec already rejected this:
  a wrong guess is worse than a denial.
- Showing the model a system-prompt section about warden (`prompt.compose`). The rules already do
  this, and the denial teaches at the moment it's needed.
- Codex, Cursor and Gemini. They have no equivalent of function hooks. `warden hook --target`
  remains the path for them once it supports more than `claude`.

## As built (2026-10-04)

The user's answers to the open questions: no `.env` edit override (1); `redact`
defaults to `live` (2); loading is set by hand, no marketplace manifest yet (3);
the pasted-prompt toast stays v1.1 (4); dismissal is per session (5); **Ask
Claude to fix** is in, as `$.prompt.fill` (6); no typed values in the pane (7);
`warden hook` stays uninstalled (8); W5 is deferred (9).

Deviations from the design above, each forced by the engine or the decisions:

- **The folder is `integrations/claude-code/`**, the name shared with the hydra
  and schedy mods, and there is no root `marketplace.json` yet.
- **Every function that takes `$` is a top-level declaration in
  `hooks/register.tsx`.** `claude plugin validate` refuses a `$` handed to a
  function in another module or to a closure inside `register`. The `lib/` and
  `ui/` split became three pure modules (`guard.ts`, `health.ts`, `shapes.ts`)
  beside it. One unmatched hook per event, so the guard, the warden-write
  refresh and the tripwire's bookkeeping share one `tool.call` hook, and the
  tripwire is one `session.append` hook that checks `door` itself.
- **F1 is done: the denial suffixes live in warden's `Decide`**, not the mod.
  An Edit/Write/NotebookEdit denial says env files are not edited directly and
  names `set`/`unset`/`clear`/`init`; a `.secrets` denial says it is never
  readable. The settings hook says the same. `Decide` gained `Detail`, which
  also returns the target W2 reports.
- **W1 also widened the settings matcher** to
  `Read|Edit|Write|NotebookEdit|Grep|Bash|Monitor`; a test pins it to the tools
  `Decide` judges. A Grep glob counts only when it names an env file: `*`
  matches `.env` but is how every search is written, and ripgrep skips hidden
  files under it anyway.
- **W3's error codes** are `no-env-file`, `refused`, `not-set`, `error` and
  `usage`. `query.ErrNoFile` re-exports the store's error, since `cli` may not
  import `store`.
- **The shape parity test is in Go** (`internal/classify/mod_parity_test.go`):
  `claude plugin test` runs with no filesystem, so the mod cannot read
  `rules.go`. `shapes.ts` lists each warden prefix literally for it.
- **The band composes** (`const below = await next(e)`, warden's rows above
  it), after the schedy mod's note that a band answering alone hides every
  plugin beneath it.
- **Tripwire tests assert on the row handed down.** The test kit has no store
  beneath `session.append`, so a test's own hook records what the mod passes to
  `next` — the row as it would be stored.
- **Warden's own output is scanned like any other** (mod 0.1.1). The first
  build skipped rows whose command's every segment began with a word named
  `warden`, and review showed that faked easily: `warden classify X $(cat f)`,
  backticks, `<(…)`, a redirect, or `./evil/warden` all passed as warden's own.
  warden never prints a value, so there is nothing to suppress: a hit in its
  output is an anomaly and is reported. A test per bypass shape pins it.
- **The guard's warden exemption covers warden alone** (found in the
  release pass). A segment starting with a word named warden was exempt
  whole, so `warden list $(cat .env)` ran the substitution and cobra echoed
  the value back in its unknown-argument error; backticks and `<(…)` did the
  same. The exemption now needs warden by name or absolute path and a segment
  with no substitution or redirect, a backtick bounds an env file name, and
  `<(` is stripped from a reader token, so `diff <(cat .env) x` is a read.
- **The mod no longer filters what it asks warden** (mod 0.1.3, after a
  post-commit review). Its prefilter, a literal `/\.env|\.secrets/`, saw a
  different string than the shell runs: `.e""nv`, `.\env`, `$'\x2eenv'`,
  `.e*v` and `.ENV` (which a case-insensitive APFS volume opens as `.env`) all
  skipped warden entirely. Every guarded call now goes to warden as written,
  one process per call as the settings hook already costs, and the symlink
  check moved into warden (`filepath.EvalSymlinks`) so the settings hook makes
  it too. Without warden, a deliberately broad heuristic holds anything that
  might spell an env file.
- **warden judges the shell's spelling, not the typed one.** `normalizeShell`
  decodes `$'…'`, substitutes variables assigned in the same command (including
  `for` lists), and drops quotes and backslashes; names compare without case;
  braces expand; a wildcard word that starts where a dotfile does counts as
  naming every protected file it can match; Grep globs like `.e*` and `.*`
  count; `LSP` is a read tool; and `ln`, `diff`, `sort`, `base64`, `curl` and
  their kind joined the readers. What stays open, by decision: a name computed
  at run time (substitution output, `eval`, a value read from a file or a
  script). Closing it would mean denying every reader whose arguments are
  computed, which catches `cat $(git rev-parse --show-toplevel)/README.md` and
  still misses `eval` and scripts — the tripwire is the backstop there.
- **Redaction closed four under-matches** (same review). Prefix rules required
  a non-word character before the value, so `\nsk_live_…` in JSON-escaped
  output and `%3Dsk_live_…` in a URL were missed; they now stand alone, as
  each prefix is distinctive. A URL password containing `@` lost only its
  first part; it now runs to the last `@`. PGP `PRIVATE KEY BLOCK`s were
  missed, and an encrypted PEM cut off before its END kept its body past the
  `Proc-Type:` header. Output past 4 MiB was not scanned at all. Case variants
  and base64-wrapped values stay out of reach, as they are for warden's own
  rules.
- **Every shape rule is linear by construction** (mod 0.1.4, second review).
  The URL rule tried an unbounded scheme from every dot and the PEM rule
  searched lazily to the end of the text for an END after every BEGIN. In
  4df856c both stayed fast only because the regex engine looks for a required
  literal first; the redaction fixes above (no JWT boundary, PGP's `( BLOCK)?`
  backreference, the greedy `@` password) defeated that, and that version took
  3 s for 128 KB of `a.a.a.` and 6 s for 512 KB of fenced BEGIN lines,
  quadrupling with each doubling, in the mod's own runtime. URL parts are bounded, PEM is found by indexing
  END markers once and pairing each BEGIN with the next END of its label within
  64 KiB, and a JWT starts only at a token boundary or after a JSON escape. A
  test holds fifteen 1 MB adversarial inputs under 500 ms each. No cap on the
  scanned length was needed once every rule is linear, so nothing is skipped.
- **The tripwire scans every row the model reads that the person did not
  type**: attachments (Monitor events, task notifications), deliveries and
  settings-hook context as well as tool rows. Only the prompt is left alone.
- **Pane keys follow `--`**, so a hand-edited `.env` key spelled like a flag
  reaches warden as a key. warden's brace expansion stops at 256 words and
  treats a word cut off there as naming an env file, so one crafted command
  cannot hang the guard.
- **The deny counter is per target in state**, and the pane footer shows it
  with the tripwire's counts; nothing about either reaches the model.
- **A key left empty in a project's `.env`, or out of it, stays off the band**
  (mod 0.1.5). `.env.example` ships blanks and an app reads a missing or empty
  value as "off", so doctor's `empty` and `drift` there were mostly keys left
  that way on purpose, and a band of them hid the findings that matter. The
  band drops both for the project, the `/env` pane drops the project's `empty`
  badge (the row already says `unset`), and "Ask Claude to fix" tells the
  model to leave such keys alone. `empty` in `~/.secrets` still shows in both,
  since that file holds only credentials. `warden doctor` itself is unchanged.

Not verified, because it needs a person at the dialog: Set… and Generate
opening warden's `osascript` dialog from `$.process.run`, in the terminal and
the desktop app. The buttons, their argv and their pending state are tested;
the dialog itself is not.
