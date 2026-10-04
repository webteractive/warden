# Warden

Check and edit environment configuration without exposing secrets.

Warden answers the questions an AI agent actually needs answered about `.env` and
`~/.secrets` — *is this key set?* *what keys exist?* *what's missing?* — while
guaranteeing no secret value reaches its output. Non-sensitive keys it will set
directly. Sensitive ones it routes through a prompt on your screen, so the value
goes from your keyboard to the file without passing through the agent.

**Warden is not a security boundary.** Nothing here stops a process from running
`cat .env`. It makes the safe path fast enough to be the obvious one.

## Install

### No Go required (recommended)

Warden compiles to a single statically linked binary with no runtime dependencies,
so the installer just drops one file into place:

```sh
curl -fsSL https://raw.githubusercontent.com/webteractive/warden/main/install.sh | sh
```

This downloads the latest release for your OS and architecture, verifies its
SHA-256 checksum, and installs to `~/.local/bin/warden`. Prebuilt binaries are
published for **macOS and Linux** on **amd64 and arm64**.

Install somewhere else with `WARDEN_INSTALL_DIR`:

```sh
curl -fsSL https://raw.githubusercontent.com/webteractive/warden/main/install.sh \
  | WARDEN_INSTALL_DIR=/usr/local/bin sh
```

> The dialog that collects secret values uses macOS `osascript`. On Linux, Warden
> falls back to a TTY prompt with echo disabled; with no TTY it refuses and prints
> the command for you to run yourself.

### From source

Requires Go 1.26+. From a clone:

```sh
./install.sh --source
```

Or without cloning:

```sh
go install github.com/webteractive/warden/cmd/warden@latest
```

### Verifying the install

```sh
warden --version      # warden 0.1.6 (ca8363f, 2026-09-05)
```

`-v` and `warden version` print the same line. The commit and date are there
because "which build is this?" is usually asked when a released version and a
local build disagree, and the tag alone cannot tell those apart.

If the command isn't found, `~/.local/bin` isn't on your `PATH` — the installer
says so and prints the line to add to your shell profile.

## Usage

```sh
warden has STRIPE_SECRET        # exit 0 if set, 1 if not. Prints nothing.
warden list                     # keys, classification, set/unset — never values
warden get APP_NAME             # public keys only; refuses secrets
warden missing                  # keys in .env.example not filled in
warden classify APP_URL         # explains why a key is secret or public
warden doctor                   # permissions, empty values, drift
warden doctor --strict          # same, but exit 1 when there are problems
warden refs                     # keys the code reads that .env does not set
warden init                     # create .env readable only by you (0600)
warden --version                # which build is this? (-v, or: warden version)
warden set APP_NAME Warden      # public keys, written directly
warden set --secret DB_PASSWORD # prompts you; the caller never sees the value
warden set --secret K --from-file ./creds.txt   # warden opens the file itself
warden set --secret K --generate                # warden mints it; nobody learns it
warden set --public CF_GROUP_ID abc123          # classify and set, for a new key
warden set --exposed CF_API_TOKEN abc123        # value is already out; record that
warden unset OLD_TOKEN          # remove a key, after you authorise it
warden clear OLD_TOKEN          # empty it, keeping the declaration
warden classify FOO --set public  # records an override, after you authorise it
warden hook                     # print the harness hook that redirects env reads here
warden vault set stripe/live --key STRIPE_SECRET   # store a key warden owns
warden vault list               # names, target keys, remaining time — never values
warden vault push stripe/live --to ~/Herd/app      # write it into that project's .env
warden mcp                      # MCP server on stdio
```

Flags: `--global` targets `~/.secrets` · `--project <dir>` names the project ·
`--json` emits machine-readable output.

**Set** means present *and* non-empty. `KEY=` counts as declared-but-unset, and
`warden has KEY` exits 1 for it.

### Creating the file

```sh
warden init            # ./.env
warden init --global   # ~/.secrets
```

Whatever makes an env file first decides who can read it, and none of the usual
candidates think about that: an editor, `touch .env`, a shell redirect, `cp
.env.example .env`, a framework installer. All of them apply the umask, which on
a default macOS or Linux account leaves a file of credentials readable by every
other account on the machine. That is the finding `warden doctor` reports most
often — and by the time it reports it, the secrets have already been written
into a world-readable file.

`warden init` creates the file at `0600` regardless of your umask. It is safe to
re-run, so it belongs in a setup script: an existing file keeps its contents
untouched, loose permissions on one are tightened, and the output says which of
those happened.

```
ok: created .env (0600)
ok: .env already exists (0600), nothing to change
ok: tightened .env from 0644 to 0600 — it was readable by other accounts on this
machine, so treat anything already stored in it as exposed
```

That last line is the honest one. Narrowing the mode now does not un-read
anything: a credential that sat in a world-readable file was readable for as
long as it sat there, and tightening the file afterwards is a fix for the next
secret, not the last one. Rotate what was in it.

The path is used exactly as given. Run this in a subdirectory of a project that
already has an `.env` above it and you get a second file there — unlike the
reading commands, `init` does not walk upward and adopt the parent's.

### Which command writes a key

One table, because picking the wrong one is the most common way to use warden
badly — and the wrong pick is usually `--secret` reached for reflexively when
the value is already out:

| Where the value is right now | Command |
|---|---|
| You don't have it; the user does | `warden set --secret KEY` |
| In a file on disk | `warden set --secret KEY --from-file PATH` |
| Doesn't exist yet, or needs rotating | `warden set --secret KEY --generate` |
| **Already printed** — by a tool, pasted by the user, in scrollback | `warden set --exposed KEY VALUE` |
| Not sensitive | `warden set KEY VALUE` |
| Not sensitive, but warden calls it secret by default | `warden set --public KEY VALUE` |

The test for the fourth row is simply *did you have this value before you ran
the command?* If yes, a prompt protects nothing it has already lost, and
`--exposed` is the honest move: it stores the value and records that it is
burned. If no, `--exposed` is the wrong answer no matter how convenient — it is
not a way around a refusal.

Warden tells you this at the moment it matters, too. `warden set KEY VALUE` on a
secret key names both commands and the test for choosing, because that refusal
is reached precisely when a caller is holding a value and about to do something
careless with it.

### Where a secret's value comes from

`--secret` says the value must not appear on a command line. It does not say
where the value comes from, and that is the choice that decides what warden can
actually promise:

| Channel | What the caller handles | Promise |
|---------|------------------------|---------|
| `--secret` (prompt) | nothing | warden controls the channel end to end |
| `--secret --from-file <path>` | a path | warden opens the file itself |
| `--secret --generate` | nothing | warden mints the value; nobody learns it |
| `--secret --stdin` | the value | **none** — see below |

The first three are structural: there is no point at which the caller could
read the value, whatever it intends. A pipe is not. `openssl rand -hex 32 |
warden set --secret K --stdin` is perfectly safe when you type it, and gives
warden nothing to stand behind when an agent types it — whoever built the
pipeline had the value before warden did. It is supported because your terminal
is yours, and the confirmation line names the channel so a reader can tell the
cases apart.

**It has to be asked for by name.** warden used to infer this channel whenever
standard input happened to be a pipe, and that was wrong in a way worth
recording: spawning a child process with `stdin=PIPE` is simply how process
runners work, so every agent that ran `warden set --secret KEY` handed warden a
pipe nobody had written a value to. warden read it, found nothing, and reported
`cancelled` — which reads as *the user declined*, so the one command agents are
told to use for secrets could not be made to work at all. A pipe on standard
input is evidence of how warden was started, never evidence that somebody piped
a credential into it. Without `--stdin` you get the prompt, whatever your caller
wired up.

```
ok: K set (secret) in .env                  ← prompt
ok: K set (secret, from creds.txt) in .env  ← file
ok: K set (secret, generated) in .env       ← generated
ok: K set (secret, from stdin) in .env      ← caller-supplied, via --stdin
```

`--generate` is the answer for a credential that has leaked. Rotating by hand
means the new value passes through whatever just leaked the old one; generating
it means the replacement is one nobody has seen.

Multi-line values work on every channel — a PEM block or a service-account JSON
is most of the reason `--from-file` is worth having:

```sh
warden set --secret TLS_KEY --from-file ./key.pem
```

The value is stored escaped on a single line, `TLS_KEY="-----BEGIN…\nMIIC…"`,
which is the form dotenv loaders already read. warden's own file stays one
assignment per line, and `doctor` reports multi-line keys as `info` so you can
see which ones they are:

```
info  multiline  TLS_KEY holds a multi-line value (16 lines), stored escaped on one line
```

**Compatibility note.** warden now interprets escape sequences inside
double-quoted values (`\n`, `\r`, `\t`, `\"`, `\\`), matching what
`vlucas/phpdotenv` and node's `dotenv` do. Single-quoted values stay literal, as
POSIX has it. If an existing `.env` has a double-quoted value containing a
literal `\n` that was meant as two characters, it now reads as a newline —
`warden doctor` names every multi-line key so you can spot one. Previously
warden read such a value differently from the application loading the same
file, which is the bug this fixes.

### When the value is already out

Sometimes a credential has been printed before you got to it — returned by a
tool, pasted into a terminal, sitting in scrollback. Laundering it through a
prompt protects nothing it has not already lost.

```sh
warden set --exposed CF_API_TOKEN abc123
```

This takes the value on the command line, and is honest about the cost: that
puts it in shell history and argv, which is durable in a way scrollback is not.
So warden records the exposure, and `doctor` keeps reporting it:

```
warn  exposed  CF_API_TOKEN was written from a command line, so its value
               reached shell history and argv
      fix      rotate it at the provider, then:
               warden set --secret CF_API_TOKEN --generate
```

The record lives in `~/.warden/exposed` and holds key names only — never a
value. It clears itself as soon as the burned value is gone: rewrite the key
through a channel that does not expose anything, or `unset` or `clear` it. The
warning stops when the fix lands rather than nagging forever.

`--exposed` changes how the value got in, not who may read it. The key stays
secret and `warden get` still refuses it.

Overwriting a key that already holds a value asks first, the same plain
confirmation `unset` and `clear` use. Provisioning an empty key does not ask —
there is nothing to lose, and a ceremony that fires when nothing is at stake is
how people learn to click through the one that matters.

### Checking a project

`doctor` reports; `doctor --strict` gates. Bare `doctor` always exits 0, so
adding `--strict` is the only thing that changes an existing script's behaviour:

```sh
warden doctor --strict          # exit 1 on any problem
warden doctor --strict=error    # exit 1 only on error-severity problems
warden doctor --refs            # also walk the source tree (slower)
```

Problems carry a stable `code` (`perms`, `empty`, `drift`, `no-example`,
`undeclared`, `unreferenced`) and a severity, so `--json` consumers key on those
rather than on the wording.

`refs` compares the source tree against the file, and needs no `.env.example` to
be right. It also says when it could not read a file, since a key referenced only
in a skipped file would look unused:

```sh
warden refs                     # both directions
warden refs --undeclared        # the code reads it, the file does not set it
warden refs --unused            # the file sets it, nothing references it
warden refs --strict            # exit 1 on an undeclared key
```

**`undeclared` is close to fact** — if the code runs, it needs the key.
**`unused` is advisory**, and always will be: `env("STRIPE_{$mode}_SECRET")` is
invisible to any static analysis, so a key built at runtime looks exactly like a
dead one. There is deliberately no `--prune`; removal goes through `warden unset`
one key at a time.

### What the scanner reads

`refs` recognises the accessor forms of four languages:

| Language | Forms |
|---|---|
| PHP / Laravel | `env('KEY')`, `Env::get('KEY')` |
| JavaScript / TypeScript | `process.env.KEY`, `process.env['KEY']`, `import.meta.env.KEY` |
| Go | `os.Getenv("KEY")`, `os.LookupEnv("KEY")` |
| Python | `os.environ['KEY']`, `os.environ.get('KEY')`, `getenv('KEY')` |

Shell and YAML interpolation — `$KEY`, `${KEY}` — is recorded as a **weak**
reference: enough to confirm a key is used, never enough to declare one. `${HOME}`
appears in every Dockerfile ever written, and a form that common cannot carry an
`undeclared` finding.

There is no extension allowlist; every text file under the root is read. Binary
files, anything over 2 MiB, and files that fail to open are skipped and reported
as such rather than passed over silently.

Vendored trees are skipped by default — `vendor`, `node_modules`, `dist`,
`build`, `.next`, `target`, `__pycache__`, `.venv`, `venv` — because code you did
not write reads its own keys, and reporting them buries every real finding.
`--include-vendor` walks them anyway, for the rare project that keeps real code
there. `.git`, `.idea` and `.vscode` are skipped under every flag.

A project with its own accessor is not stuck with the built-in list. `--pattern`
takes a regex whose **first capture group** is the key, is repeatable, and joins
the strong set — so a match declares a key just as `env()` would:

```sh
warden refs --pattern "config\(\s*'([A-Z_][A-Z0-9_]*)'"
warden doctor --refs --pattern '...' --include-vendor
```

`--pattern` and `--include-vendor` work identically on `doctor --refs`, which
runs the same walk.

### Removing a key

```sh
warden unset OLD_TOKEN          # removes every assignment of it
warden clear OLD_TOKEN          # keeps the declaration, empties the value
```

Both work on secret keys, because deleting reveals nothing — and hand-editing the
file is the operation these exist to replace. A key that currently holds a value
needs confirmation on your screen first: nothing is disclosed by a deletion, but
the value may not be recoverable, so the risk being guarded is destruction.

`unset` removes **every** assignment of the key. A duplicated key resolves to its
last assignment, so removing only that line would leave an earlier value live
while looking like it worked.

### The harness hook

`warden hook` prints a `PreToolUse` entry that denies direct reads of `.env` and
`~/.secrets` and answers with the warden command to use instead:

```sh
warden hook                       # print it; writes nothing
warden hook --install --yes       # merge it into .claude/settings.json
warden hook --install --yes --global   # ...or ~/.claude/settings.json
warden hook --check               # installed? is warden on PATH? can it run the guard?
warden hook --uninstall --yes
warden hook --install --settings path/to/settings.json --yes   # aim it elsewhere
```

`--install` and `--uninstall` without `--yes` print what they *would* do and
write nothing, so a dry run is the default rather than an option. `--target`
names the harness and defaults to `claude`, the only one supported today;
another value is refused rather than written half-correctly.

**What it covers is wider than `.env`.** Any `.env.*` variant counts —
`.env.local`, `.env.production`, `.env.staging` — along with `.secrets`. Four
names are deliberately left readable, because they hold key names and no values,
and blocking them is the fastest way to have the whole hook removed in
irritation:

```
.env.example  .env.schema  .env.sample  .env.dist
```

A denial is never bare. It answers with the warden command that gets the same
answer, since an unexplained refusal just produces three more attempts at a
workaround.

Installing preserves every other setting and every other hook, replaces warden's
own entry rather than appending a second copy, and refuses a settings file it
cannot parse rather than rewriting it.

`--check` also runs the guard on the binary it finds on `PATH`. That matters more
than it looks: the guard **fails open**, so a `warden` predating `hook` means
every read is allowed while the hook looks installed. After upgrading, reinstall
so `PATH` has the new binary.

**This is a speed bump list, not a sandbox.** It closes the path taken by
accident and teaches the replacement at the moment of need. A command can still
read a file in ways no matcher enumerates — `python -c`, a heredoc, a base64
round trip, a build script that loads dotenv. Warden is not a boundary and the
hook does not make it one.

### The vault

`.env` and `~/.secrets` hold credentials that already exist somewhere. The vault
is warden's own storage: a credential lives there once, and gets pushed into
whatever project needs it.

```sh
warden vault init [--passphrase]                 # choose the at-rest mode
warden vault set <name> --key <KEY> [--ttl 8h]   # create or replace; always prompts
warden vault list [--json]                       # names, keys, remaining time
warden vault has <name>                          # exit 0 if present and unexpired
warden vault edit <name> [--name new] [--key K] [--ttl 8h|none]
warden vault rm <name>                           # confirmation on your screen
warden vault push <name> --to <dir>|global [--as KEY] [--yes] [--force]
```

An entry is addressed by a **name** you choose and separately records the **env
key** it lands as. That indirection is what lets two projects with different
`DB_PASSWORD` values coexist as `acme/db` and `beta/db` — a store addressed by
env key can only hold one of them.

`--key` may be omitted when the name is already a valid env key, so `warden vault
set STRIPE_SECRET` needs nothing further.

**There is no `warden vault get`.** No command renders a vault value, and that is
the design rather than a refusal — nothing needs gating because nothing asks. A
value leaves the vault only through `push`, which hands it to a destination file
inside a `secret.Secret`. Exit code 2 never fires in the vault.

`push` is the operation that moves a credential from a file that exists nowhere
else into one that may well be committed, so it confirms on your screen. `--yes`
skips that on the CLI and is unavailable to the MCP server. An already-set
destination key is refused unless you pass `--force`.

### Temporary entries

`--ttl` takes `30m`, `8h`, `7d`. **The maximum is 30 days, and a longer one is
refused rather than shortened** — silently clamping would have you believe a
credential lives for a year while it dies in a month.

An expired entry is indistinguishable from one that never existed: `has` exits 1,
`list` omits it, `push` fails as absent, and it is dropped from the file at the
next write. An entry with no `--ttl` is permanent and unbounded, and that
asymmetry is the point: the cap exists to stop `--ttl 8760h` masquerading as
permanent.

### At rest

The vault is one file at `~/.warden/vault`, mode `0600`: a plaintext header
naming how to unseal it, then a single AES-256-GCM blob. Entry names are inside
the seal, because `acme/prod-db` is itself worth not leaking.

The master key lives in your OS keyring by default — the macOS Keychain, or
libsecret on Linux — which is what keeps every other command free of a passphrase
prompt. `vault init --passphrase` derives it with Argon2id instead.

**Be clear about what this buys.** Encryption at rest defends against a synced
backup, a stolen laptop with a locked keychain, a `cat ~/.warden/vault`, and an
agent grepping your home directory. It does **not** defend against a local
process: warden's release binaries are built with `CGO_ENABLED=0`, so keyring
access goes through `/usr/bin/security` and `secret-tool`, and a keychain ACL
therefore protects *those tools* rather than warden. Anything on your machine
that can run `security` can read the master key. `--passphrase` narrows that gap
at the cost of a dialog on every command, and makes the vault unusable from the
MCP server where no prompt may be available.

This is the same line warden draws everywhere else. It is written down so
"encrypted" does not imply a boundary that isn't there.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | success |
| 1 | key absent or unset |
| 2 | refused — the key is secret |
| 3 | error — no `.env`, parse failure, cancelled prompt |

## Classification

A key is secret unless proven otherwise. Precedence, first match wins:

1. **Value shape** — `sk_live_`, `ghp_`, `AKIA`, PEM blocks, URLs carrying
   `user:pass@`. Unwaivable: a schema cannot mark a live credential public.
2. **User schema** — the matching project and key in `~/.warden/schema`.
3. **Legacy project schema** — an existing `.env.schema` beside `.env`.
4. **Public allowlist** — framework keys like `APP_NAME`, `DB_HOST`,
   `MAIL_FROM_NAME`, and everything `VITE_*` (those ship to browsers).
5. **Secret name patterns** — `*_KEY`, `*SECRET*`, `*TOKEN*`, `*PASSWORD*`, `*_DSN`, …
6. **Default: secret.**

Run `warden classify <KEY>` to see which layer or rule fired.

### Overriding a classification

`classify --set` records an override for the current project in the central
`~/.warden/schema` registry:

```sh
warden classify MY_PUBLIC_KEY --set public
warden classify INTERNAL_MODE --set secret
```

Making a key public is gated: you retype the key to confirm, because that turns
a value warden refuses to print into one it will emit. The gate is waived when
the key holds no value — nothing can be disclosed by classifying an empty key —
which is what lets a new key be classified and set in one step:

```sh
warden set --public CF_GROUP_ID abc123
```

That covers the common case, and only that case: a key that is secret because
warden fails closed, not because any rule matched it. `warden classify
CF_GROUP_ID` tells you which applies. Two things send you to `classify --set
public` and its full ceremony instead:

- **The key already holds a value.** That is the case the retype exists for.
- **A rule matched the name.** `DB_PASSWORD` is secret because `*PASSWORD*`
  recognised it, and overriding a rule is a claim that the rule is wrong —
  worth a deliberate command, not a flag on the one that also supplies the
  value.

A credential-shaped value is refused outright, and the refusal changes nothing:
a `set --public` that fails leaves the key classified exactly as it was.

Choosing the secret channel also classifies. `warden set --secret VITE_ANALYTICS_ID`
records the key as secret, because otherwise the allowlist would win and `warden
get` would hand back the value you just stored out of sight.

The registry is JSON keyed first by the canonical project root, then by key:

```json
{
  "/Users/example/code/shop": {
    "INTERNAL_MODE": "secret",
    "MY_PUBLIC_KEY": "public"
  }
}
```

It contains class names and project paths, never environment values. Existing
`.env.schema` files are still read as a compatibility fallback, but warden no
longer creates or edits them. A central entry wins when both files name the same
key.

The two directions are not equally dangerous, so they are not equally easy.
Marking a key **public** is the only operation that turns a value warden refuses
to print into one it will emit, so it opens a prompt this process owns and asks
you to **retype the key name** — a button reachable by muscle memory is too weak
a gate for that. Marking a key **secret** only tightens, so it takes a plain
confirmation. Declining, mistyping, and letting the dialog time out all write
nothing and exit 3.

Two refusals land before you are asked anything:

- **`--global` is refused.** `~/.secrets` holds secrets by definition, so an
  override there would only serve to unmask one.
- **A credential-shaped value cannot be made public.** Shape outranks the schema,
  so the entry would be inert — warden refuses rather than writing a line that
  silently does nothing.

A key that is secret only by *name* is fair game: correcting `FOO_KEY` or
`SESSION_SECRET_TIMEOUT` is exactly what this is for.

`--set` is **CLI-only and deliberately absent from the MCP server**, so an agent
can ask what a key's class is but never change it.

## MCP surface

`warden mcp` serves the same surface on stdio: `env_has`, `env_list`,
`env_missing`, `env_get`, `env_doctor`, `env_init`, `env_refs`, `env_set`,
`env_request_secret`, `env_unset`, `env_clear`, `env_classify`, plus the vault's
`vault_list`, `vault_has`, `vault_request_secret`, `vault_delete` and
`vault_push`. Every env tool takes an optional `project` path, because the
server's working directory will not reliably match the project under discussion.

`env_init` is on this surface on purpose, unlike the vault's `init`. An agent
that cannot call it does not skip creating the file — it creates it some other
way, and `touch`, a redirect and a copy of `.env.example` all apply the umask.
Since the tool reveals nothing and destroys nothing, making the safe path the
available one is strictly better than leaving agents the unsafe ones.

Five things are deliberately CLI-only, and a test makes each omission deliberate
rather than accidental: `classify --set` (an agent may ask a key's class, never
change it), `hook` (a tool that edits the harness's own permission config is a
privilege-escalation primitive), `mcp` itself, and the vault's `init` and `edit`
(the first chooses how the vault is protected at rest; the second would let an
agent quietly extend a credential's lifetime). `vault_push` exists but cannot
skip its confirmation — `--yes` is CLI-only, and `vaultPushArgs` has no field
for it.

## How the guarantee is enforced

Four mechanisms, all checked by tests rather than convention:

- **`secret.Secret`** intercepts every `fmt` verb and `encoding/json`, so a stray
  log line or JSON encode emits `<redacted>`. `Expose()` is the single escape
  hatch, and a test caps how many production call sites may exist.
- **A canary suite** runs every command against a fixture whose values are unique
  markers and asserts none appear in stdout or stderr. Registering a new command
  without adding it to the coverage table fails the build.
- **An architecture test** asserts `internal/cli`, `internal/mcpserver` and
  `cmd/warden` never import `internal/store`, `internal/vault` or
  `internal/keyring` directly — so no surface can reach a raw value without
  passing a classification first, and none can reach the key that unseals the
  vault. A second one holds
  `internal/refs` to the same line: it deals in key names and file paths, and is
  structurally unable to hold a value.
- **A parity test** maps every CLI command to the MCP tool that covers it, and
  fails the build on either side gaining something the table does not account
  for. `env_doctor` was missing for an entire release because nothing checked.

`~/.secrets` is parsed as text and never sourced; a `$(…)` in a value is read as
literal characters, not executed.

## Design

See `docs/superpowers/specs/2026-08-10-warden-design.md` and the implementation
plan in `docs/superpowers/plans/2026-08-10-warden.md`.

Later work has one spec per feature in `docs/superpowers/specs/`. Implemented:
`doctor --strict`, `env_doctor` and the parity test, `unset`/`clear`, `refs`,
`hook`, and the `vault`. Proposed but not built: `copy`, `scan`, `run`,
`example --sync`, `--file`/`diff`, rotation age, and the expanded shape rules.
