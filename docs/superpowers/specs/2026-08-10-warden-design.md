# Warden — design

**Date:** 2026-08-10
**Status:** approved, not yet implemented

## Problem

Global rules forbid agents from reading `.env` files and from reading `~/.secrets` under any
circumstance. The bans are correct, but they leave agents with no way to answer trivial
questions: *is `STRIPE_SECRET` set in this project?* *Which keys does `.env.example` declare
that `.env` is missing?* *Can I set `APP_NAME` without bothering the user?*

Today the fallbacks are guessing, hand-rolled `sed 's/=.*/=<redacted>/'` one-liners, or handing
the user a command to run themselves. Every one of those costs an interruption or risks a
mistake.

Warden closes that gap. It is a query surface over environment configuration that never emits a
secret value, plus a write path that lets agents set non-sensitive keys directly and routes
sensitive ones through a prompt the agent cannot observe.

**What Warden is not:** a security boundary. Nothing in Warden prevents an agent from running
`cat .env`. The rules do that. Warden makes the *permitted* path fast enough that the forbidden
one stops being tempting. Any claim stronger than that would be false.

## Scope

Two stores, one interface:

- **Project `.env`** — located by walking up from the working directory, or named with
  `--project <path>`.
- **Global `~/.secrets`** — targeted with `--global`.

Deliverable is a single Go binary at `~/AI/warden`, installed to `~/.local/bin` by an
`install.sh`, matching the pattern already used by `hydra` and `diary`. The MCP server is a
subcommand of that same binary rather than a separate project, so the two surfaces cannot drift
apart.

## Architecture

```
cli/          argument parsing, exit codes, human output
mcp/          stdio MCP server
  ↓ both call ↓
query/        read-only API — returns booleans, key names, redacted rows
write/        public path (direct) and secret path (dialog)
  ↓ both call ↓
classify/     secret-vs-public decision for a key
store/        backend interface: Names(), Get(), Set()
  ├ dotenv       project .env
  └ secretsfile  ~/.secrets
```

The boundary that matters is `store` → `query`. `store` deals in values; `query` structurally
cannot return one. Every read-side consumer goes through `query`, so there is no code path from
a stored secret to an output stream.

### The `Secret` type

Values leave `store` as `type Secret string`. Its `String()`, `Format()`, and `MarshalJSON()`
all return `<redacted>`. An accidental `fmt.Printf("%v", …)`, log line, or JSON encode anywhere
in the codebase — now or in future changes — emits nothing. The core safety property is enforced
by the type system instead of by author discipline.

### `~/.secrets` is parsed, never sourced

The file is shell syntax (`export KEY=value` and bare `KEY=value`, quoted and unquoted). Warden
parses it as text. It never sources it into a shell, because sourcing would execute any command
substitution present in the file. A `$(whoami)` in a value is read as the literal nine
characters.

## Classification

Resolved in strict precedence order. First match wins.

1. **Value shape, and it is unwaivable.** Available precisely because Warden may read what it
   will not emit. A value matching `sk_live_`, `sk_test_`, `ghp_`, `github_pat_`, `AKIA`,
   `xoxb-`, `-----BEGIN`, or a URL carrying a `user:pass@` userinfo component is secret
   regardless of its key name. This catches `APP_URL=https://admin:hunter2@staging.example.com`,
   which every name-based rule would wave through.

   It deliberately outranks the schema below it. An override exists to fix a heuristic miss, not
   to unmask a live credential, so no `.env.schema` entry can make a demonstrable API key
   readable.
2. **`.env.schema` override** — optional per-project file declaring `KEY=public|secret`. Written
   only where the heuristics are wrong; most projects will never have one.
3. **Public allowlist.** `APP_NAME`, `APP_ENV`, `APP_DEBUG`, `APP_URL`, `APP_LOCALE`,
   `APP_TIMEZONE`, `LOG_CHANNEL`, `LOG_LEVEL`, `LOG_STACK`, `DB_CONNECTION`, `DB_HOST`,
   `DB_PORT`, `DB_DATABASE`, `DB_USERNAME`, `CACHE_STORE`, `CACHE_PREFIX`, `QUEUE_CONNECTION`,
   `SESSION_DRIVER`, `SESSION_LIFETIME`, `BROADCAST_CONNECTION`, `FILESYSTEM_DISK`,
   `MAIL_MAILER`, `MAIL_HOST`, `MAIL_PORT`, `MAIL_FROM_ADDRESS`, `MAIL_FROM_NAME`,
   `MAIL_SCHEME`, `VITE_*`.

   `VITE_*` is public by definition — those values are compiled into browser bundles.

   `DB_USERNAME` is a deliberate call: not a credential on its own, frequently needed, and
   fail-closed would otherwise hide it. Reversible by moving it to rule 4.
4. **Secret name patterns.** `*_KEY`, `*SECRET*`, `*TOKEN*`, `*PASSWORD*`, `*PASSWD*`, `*_PWD`,
   `*_DSN`, `*PRIVATE*`, `*CREDENTIAL*`, `*SALT*`, `*SIGNATURE*`, `*_CERT`, `DATABASE_URL`,
   `REDIS_URL`.
5. **Default: secret.** Fail closed. An unrecognised key is never treated as safe.

`warden classify <KEY>` reports which rule matched, so a surprising result is diagnosable rather
than mysterious.

## Command surface

```
warden has <KEY>            exit 0/1, prints nothing
warden list                 KEY / class / state table; never values
warden get <KEY>            public keys only; exit 2 on a secret
warden missing              keys in .env.example absent from .env
warden set <KEY> <VALUE>    public only; exit 2 + guidance on a secret
warden set --secret <KEY>   native dialog; accepts NO value argument
warden classify <KEY>       explains the matched rule
warden doctor               perms, empty values, duplicate keys, drift vs .env.example
warden mcp                  stdio MCP server
```

Global flags: `--global` (target `~/.secrets`), `--project <path>`, `--json`.

### Definitions

- **Set** means present *and* non-empty. `KEY=` in a file counts as declared-but-unset, and
  `warden has KEY` exits 1 for it. This is what a caller actually wants to know — a key with an
  empty value is not usable, and reporting it as present would be worse than useless.
- **`list`** enumerates keys that appear in the target file, with `state` of `set` or `unset` per
  the definition above. Keys declared in `.env.example` but absent from `.env` are *not* listed
  here; that is `missing`'s job.
- **`missing`** is project-only. `--global` is rejected, because `~/.secrets` has no
  `.env.example` counterpart to diff against.

Two commands are load-bearing:

- **`set --secret` takes no value argument.** Rejected at argument parsing, not merely ignored.
  If it accepted one, a value would eventually be passed on a command line, landing in shell
  history and in the agent transcript. The dialog is the only way in.
- **`has` prints nothing.** Status only — nothing to accidentally log or echo.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | yes / success |
| 1 | no — key absent or unset |
| 2 | refused by policy — key is secret |
| 3 | error — no `.env` found, parse failure, dialog cancelled or timed out |

## Write path

**Mechanics.** Surgical line edits, never parse-then-rewrite. Comments, blank lines, key order,
and quoting style outside the target line survive byte-for-byte. Writes go to a temp file in the
same directory, inherit the original's mode, then `rename()` — an interrupted write cannot
truncate a `.env`. An existing key is replaced in place; a new key is appended. `set` against a
missing `.env` errors unless `--create`. Warden refuses to write a file containing merge-conflict
markers.

**Public keys** are set directly by the agent, no prompt.

**Secret keys** go through a native macOS dialog (an `NSAlert` run as JXA by `osascript`) with a
secure field that **Reveal** swaps for a multi-line one, kept out of screen capture, titled with the
key name *and the target file path* so the user sees what they are authorising before typing.
60-second timeout. Cancel or timeout writes nothing and exits 3. The typed value lands in a
`Secret`, goes straight to the file, and is zeroed.

Success prints exactly:

```
ok: STRIPE_SECRET set (secret) in ~/Herd/campaignbuilder/.env
```

No value — and deliberately no length or hash either, since a length leak is still a leak.

Where `osascript` is unavailable, Warden falls back to a TTY prompt with echo disabled; with no
TTY it refuses and prints a command for the user to run themselves.

## MCP surface

`warden mcp` serves stdio MCP with tools mirroring the CLI one-to-one: `env_has`, `env_list`,
`env_missing`, `env_get`, `env_set`, `env_request_secret`, `env_classify`. Every tool takes an
optional `project` path, because the MCP server's working directory will not reliably match the
project under discussion.

Registration in `~/AI/dotfiles/mcp/servers.json` is deferred — see Out of scope.

## Invariants

Everything else in this document is negotiable. These are the point of the tool:

1. No secret value reaches stdout, stderr, or a log — under any command, flag, or error path.
2. `Secret` redacts under every formatting verb and JSON encode.
3. `~/.secrets` is parsed, never executed.
4. An unmatched key classifies as secret.
5. A refusal writes nothing and exits non-zero.
6. A write preserves every byte outside the target line.
7. A cancelled or timed-out dialog is a complete no-op.

## Testing

**The canary test** guards invariant 1 and is the centrepiece. A fixture `.env` in which every
value is a unique random string; every command × every flag × every error path is executed and
both output streams are captured; the test asserts no secret-key canary appears anywhere. The
table is built from the registered command list, so **adding a command without adding it to the
test fails the build**. This is what keeps the guarantee true as the tool grows.

Supporting tests:

- **Classification tables**, including the cases that are easy to get wrong: `APP_KEY` → secret;
  `VITE_APP_NAME` → public; `APP_URL` carrying `user:pass@` → secret by shape, overriding the
  public allowlist; `.env.schema` override beating every heuristic.
- **Golden-file round-trips** proving a `set` preserves comments, ordering, quoting style, CRLF
  line endings, and trailing-newline state.
- **`~/.secrets` parser**, asserting `$(whoami)` in a value is read as literal text with no side
  effect, and that both `export KEY=v` and `KEY=v` forms parse.
- **MCP stdio protocol tests** over the tool surface.
- **Dialog** behind an interface with a fake for tests, plus one manual smoke test of the real
  `osascript` path — that one cannot be automated honestly, and pretending otherwise would be
  worse than documenting it.

## Out of scope for v1

- Keychain-backed value references. Herd serves Laravel apps via php-fpm rather than a shell, so
  a `warden run --` shim cannot wrap them; references would require a custom dotenv loader in
  every project. Revisit for `~/.secrets` alone, where `~/.zshrc` is a wrappable entry point.
- Migrating `~/.secrets` anywhere.
- Team sync, sharing, and rotation.
- Multi-environment files (`.env.staging`, `.env.testing`).
- CI validation.
- Editing `.env.example`.
- Rewriting `rules/env-files.md` and `rules/secrets-file.md` in dotfiles, and registering the MCP
  server in `mcp/servers.json`. Deliberately deferred: use the CLI directly for a while first and
  let real friction decide the rule wording.

## Repository

`~/AI/warden`, Go, `git init` only — no GitHub repo. `install.sh` places the binary in
`~/.local/bin`, matching `hydra` and `diary`.
